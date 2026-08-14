//! Mach-O Objective-C runtime metadata analysis.
//!
//! Parses the Objective-C ABI v2 metadata embedded in `__objc_classlist`,
//! `__objc_catlist`, `__objc_protolist`, and related sections to expose
//! classes, methods, selectors, protocols, instance variables, and
//! categories.

use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObjcError {
    TruncatedData { offset: usize, needed: usize },
    InvalidPointer(u64),
    InvalidNameOffset(u64),
    CyclicClassHierarchy,
    TooManyMethods(usize),
    TooManyClasses(usize),
    StringNotTerminated(u64),
    UnsupportedAbi(u8),
    MissingSection(String),
}

impl std::fmt::Display for ObjcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TruncatedData { offset, needed } => write!(
                f,
                "truncated ObjC data at offset {offset:#x}, need {needed}"
            ),
            Self::InvalidPointer(p) => write!(f, "invalid ObjC pointer {p:#x}"),
            Self::InvalidNameOffset(o) => write!(f, "invalid name offset {o:#x}"),
            Self::CyclicClassHierarchy => write!(f, "cyclic ObjC class hierarchy"),
            Self::TooManyMethods(n) => write!(f, "too many methods: {n}"),
            Self::TooManyClasses(n) => write!(f, "too many classes: {n}"),
            Self::StringNotTerminated(o) => write!(f, "string not null-terminated at {o:#x}"),
            Self::UnsupportedAbi(v) => write!(f, "unsupported ObjC ABI version {v}"),
            Self::MissingSection(s) => write!(f, "missing section: {s}"),
        }
    }
}

impl std::error::Error for ObjcError {}

// ---------------------------------------------------------------------------
// ObjcSelector
// ---------------------------------------------------------------------------

/// An Objective-C method selector.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ObjcSelector {
    /// The selector string, e.g. `"initWithFrame:"`.
    pub name: String,
    /// Virtual address of the selector reference.
    pub ref_addr: u64,
}

impl ObjcSelector {
    pub fn new(name: impl Into<String>, ref_addr: u64) -> Self {
        Self {
            name: name.into(),
            ref_addr,
        }
    }

    /// Number of arguments implied by the selector (count of colons).
    #[must_use] 
    pub fn argument_count(&self) -> usize {
        self.name.chars().filter(|&c| c == ':').count()
    }

    /// `true` when this looks like a property getter (no colons, lowercase start).
    #[must_use] 
    pub fn is_likely_getter(&self) -> bool {
        self.argument_count() == 0
            && self
                .name
                .chars()
                .next()
                .is_some_and(char::is_lowercase)
    }

    /// `true` when this looks like a property setter (`setXxx:`).
    #[must_use] 
    pub fn is_likely_setter(&self) -> bool {
        self.argument_count() == 1 && self.name.starts_with("set")
    }
}

// ---------------------------------------------------------------------------
// ObjcMethod
// ---------------------------------------------------------------------------

/// An Objective-C method entry.
#[derive(Debug, Clone)]
pub struct ObjcMethod {
    pub selector: String,
    /// Type encoding string (e.g. `"v16@0:8"`).
    pub type_encoding: String,
    /// Implementation function virtual address.
    pub imp: u64,
    /// `true` for class methods (`+`), `false` for instance methods (`-`).
    pub is_class_method: bool,
}

impl ObjcMethod {
    pub fn new(
        selector: impl Into<String>,
        type_encoding: impl Into<String>,
        imp: u64,
        is_class: bool,
    ) -> Self {
        Self {
            selector: selector.into(),
            type_encoding: type_encoding.into(),
            imp,
            is_class_method: is_class,
        }
    }

    /// Return value type from the encoding (first character before `@`/`:` etc.).
    #[must_use] 
    pub fn return_type_char(&self) -> Option<char> {
        self.type_encoding.chars().next()
    }

    /// `true` when the method returns void.
    #[must_use] 
    pub fn returns_void(&self) -> bool {
        self.return_type_char() == Some('v')
    }

    /// Prefix character for display ('+' or '-').
    #[must_use] 
    pub const fn prefix(&self) -> char {
        if self.is_class_method { '+' } else { '-' }
    }

    /// Display format: `+[ClassName method:]`.
    #[must_use] 
    pub fn format_with_class(&self, class_name: &str) -> String {
        format!("{}[{} {}]", self.prefix(), class_name, self.selector)
    }
}

// ---------------------------------------------------------------------------
// ObjcIvar
// ---------------------------------------------------------------------------

/// An Objective-C instance variable.
#[derive(Debug, Clone)]
pub struct ObjcIvar {
    pub name: String,
    /// Type encoding of the ivar.
    pub type_encoding: String,
    /// Offset within the object layout.
    pub offset: u32,
    /// Size in bytes.
    pub size: u32,
    /// Alignment expressed as log2(alignment).
    pub alignment: u32,
}

impl ObjcIvar {
    pub fn new(
        name: impl Into<String>,
        type_enc: impl Into<String>,
        offset: u32,
        size: u32,
        align: u32,
    ) -> Self {
        Self {
            name: name.into(),
            type_encoding: type_enc.into(),
            offset,
            size,
            alignment: align,
        }
    }

    /// Actual alignment value in bytes.
    #[must_use] 
    pub const fn alignment_bytes(&self) -> u32 {
        1u32 << self.alignment
    }
}

// ---------------------------------------------------------------------------
// ObjcProtocol
// ---------------------------------------------------------------------------

/// An Objective-C protocol definition.
#[derive(Debug, Clone)]
pub struct ObjcProtocol {
    pub name: String,
    /// Protocols this protocol extends.
    pub base_protocols: Vec<String>,
    pub instance_methods: Vec<ObjcMethod>,
    pub class_methods: Vec<ObjcMethod>,
    pub optional_instance_methods: Vec<ObjcMethod>,
    pub optional_class_methods: Vec<ObjcMethod>,
    /// Virtual address of the `protocol_t` structure.
    pub addr: u64,
}

impl ObjcProtocol {
    pub fn new(name: impl Into<String>, addr: u64) -> Self {
        Self {
            name: name.into(),
            base_protocols: vec![],
            instance_methods: vec![],
            class_methods: vec![],
            optional_instance_methods: vec![],
            optional_class_methods: vec![],
            addr,
        }
    }

    /// Total number of required methods.
    #[must_use] 
    pub const fn required_method_count(&self) -> usize {
        self.instance_methods.len() + self.class_methods.len()
    }

    /// Total number of optional methods.
    #[must_use] 
    pub const fn optional_method_count(&self) -> usize {
        self.optional_instance_methods.len() + self.optional_class_methods.len()
    }
}

// ---------------------------------------------------------------------------
// ObjcClass
// ---------------------------------------------------------------------------

/// Flags extracted from the class `flags` field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObjcClassFlags(pub u32);

impl ObjcClassFlags {
    pub const IS_SWIFT: u32 = 0x8;
    pub const IS_ROOT_CLASS: u32 = 0x1;
    pub const HAS_CXX_STRUCTORS: u32 = 0x4;
    pub const IS_METACLASS: u32 = 0x1; // in meta_class data flags

    #[must_use] 
    pub const fn is_swift(self) -> bool {
        self.0 & Self::IS_SWIFT != 0
    }
    #[must_use] 
    pub const fn is_root(self) -> bool {
        self.0 & Self::IS_ROOT_CLASS != 0
    }
    #[must_use] 
    pub const fn has_cxx_structors(self) -> bool {
        self.0 & Self::HAS_CXX_STRUCTORS != 0
    }
}

/// A fully-parsed Objective-C class.
#[derive(Debug, Clone)]
pub struct ObjcClass {
    pub name: String,
    /// Name of the superclass (empty for root classes).
    pub superclass_name: String,
    pub instance_methods: Vec<ObjcMethod>,
    pub class_methods: Vec<ObjcMethod>,
    pub instance_variables: Vec<ObjcIvar>,
    pub protocols: Vec<String>,
    pub properties: Vec<ObjcProperty>,
    pub flags: ObjcClassFlags,
    /// Virtual address of the `class_t` structure.
    pub addr: u64,
    /// Virtual address of the `metaclass_t` structure.
    pub meta_addr: u64,
    pub instance_size: u32,
}

impl ObjcClass {
    pub fn new(name: impl Into<String>, addr: u64) -> Self {
        Self {
            name: name.into(),
            superclass_name: String::new(),
            instance_methods: vec![],
            class_methods: vec![],
            instance_variables: vec![],
            protocols: vec![],
            properties: vec![],
            flags: ObjcClassFlags(0),
            addr,
            meta_addr: 0,
            instance_size: 0,
        }
    }

    /// `true` if this class is a root class (has no superclass).
    #[must_use] 
    pub const fn is_root_class(&self) -> bool {
        self.superclass_name.is_empty() || self.flags.is_root()
    }

    /// `true` if this class is a Swift class.
    #[must_use] 
    pub const fn is_swift(&self) -> bool {
        self.flags.is_swift()
    }

    /// Find an instance method by selector name.
    #[must_use] 
    pub fn find_method(&self, selector: &str) -> Option<&ObjcMethod> {
        self.instance_methods
            .iter()
            .find(|m| m.selector == selector)
    }

    /// All method names (instance + class).
    #[must_use] 
    pub fn all_selector_names(&self) -> Vec<&str> {
        self.instance_methods
            .iter()
            .chain(self.class_methods.iter())
            .map(|m| m.selector.as_str())
            .collect()
    }

    /// `true` when the class conforms to a given protocol name.
    #[must_use] 
    pub fn conforms_to(&self, protocol: &str) -> bool {
        self.protocols.iter().any(|p| p == protocol)
    }
}

/// An Objective-C property (from `@property`).
#[derive(Debug, Clone)]
pub struct ObjcProperty {
    pub name: String,
    pub attribute_string: String,
    pub is_readonly: bool,
    pub is_copy: bool,
    pub is_retain: bool,
    pub is_nonatomic: bool,
    pub is_weak: bool,
}

impl ObjcProperty {
    /// Parse from an `ObjC` property attribute string, e.g. `"Tq,N,Vcount"`.
    pub fn from_attribute_string(name: impl Into<String>, attrs: impl Into<String>) -> Self {
        let name = name.into();
        let attrs_str: String = attrs.into();
        let mut p = Self {
            name,
            attribute_string: attrs_str.clone(),
            is_readonly: false,
            is_copy: false,
            is_retain: false,
            is_nonatomic: false,
            is_weak: false,
        };
        for part in attrs_str.split(',') {
            match part {
                "R" => p.is_readonly = true,
                "C" => p.is_copy = true,
                "&" => p.is_retain = true,
                "N" => p.is_nonatomic = true,
                "W" => p.is_weak = true,
                _ => {}
            }
        }
        p
    }
}

// ---------------------------------------------------------------------------
// ObjcCategory
// ---------------------------------------------------------------------------

/// An Objective-C category.
#[derive(Debug, Clone)]
pub struct ObjcCategory {
    pub name: String,
    pub class_name: String,
    pub instance_methods: Vec<ObjcMethod>,
    pub class_methods: Vec<ObjcMethod>,
    pub protocols: Vec<String>,
    pub properties: Vec<ObjcProperty>,
    /// Virtual address of the `category_t` structure.
    pub addr: u64,
}

impl ObjcCategory {
    pub fn new(name: impl Into<String>, class_name: impl Into<String>, addr: u64) -> Self {
        Self {
            name: name.into(),
            class_name: class_name.into(),
            instance_methods: vec![],
            class_methods: vec![],
            protocols: vec![],
            properties: vec![],
            addr,
        }
    }

    /// `true` if this category adds any methods.
    #[must_use] 
    pub const fn adds_methods(&self) -> bool {
        !self.instance_methods.is_empty() || !self.class_methods.is_empty()
    }
}

// ---------------------------------------------------------------------------
// MethodList parser
// ---------------------------------------------------------------------------

/// Parse an `ObjC` method list from raw bytes.
/// Layout of `method_t` (relative method lists not supported here):
///   [`name_offset`: u32][types_offset: u32][imp: u64]  (24 bytes, 64-bit)
pub fn parse_method_list(
    data: &[u8],
    is_class_method: bool,
    get_string: &dyn Fn(u64) -> Option<String>,
) -> Result<Vec<ObjcMethod>, ObjcError> {
    if data.len() < 8 {
        return Err(ObjcError::TruncatedData {
            offset: 0,
            needed: 8,
        });
    }
    let flags = u32::from_le_bytes(data[0..4].try_into().unwrap());
    let count = u32::from_le_bytes(data[4..8].try_into().unwrap()) as usize;
    const MAX: usize = 65536;
    if count > MAX {
        return Err(ObjcError::TooManyMethods(count));
    }

    let uses_relative_offsets = flags & 0x8000_0000 != 0;
    let entry_size = if uses_relative_offsets {
        12usize
    } else {
        24usize
    };
    let mut methods = Vec::with_capacity(count);
    let mut offset = 8;

    for _ in 0..count {
        if offset + entry_size > data.len() {
            return Err(ObjcError::TruncatedData {
                offset,
                needed: entry_size,
            });
        }
        let (selector, type_enc, imp) = if uses_relative_offsets {
            // Relative method list: three relative offsets (i32)
            let sel_rel = i32::from_le_bytes(data[offset..offset + 4].try_into().unwrap());
            let typ_rel = i32::from_le_bytes(data[offset + 4..offset + 8].try_into().unwrap());
            let imp_rel = i32::from_le_bytes(data[offset + 8..offset + 12].try_into().unwrap());
            let sel_va = (offset as i64 + i64::from(sel_rel)).cast_unsigned();
            let _typ_va = (offset as i64 + 4 + i64::from(typ_rel)).cast_unsigned();
            let imp_va = (offset as i64 + 8 + i64::from(imp_rel)).cast_unsigned();
            let sel = get_string(sel_va).unwrap_or_default();
            (sel, String::new(), imp_va)
        } else {
            let sel_ref = u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap());
            let typ_ref = u64::from_le_bytes(data[offset + 8..offset + 16].try_into().unwrap());
            let imp = u64::from_le_bytes(data[offset + 16..offset + 24].try_into().unwrap());
            let sel = get_string(sel_ref).unwrap_or_default();
            let typ = get_string(typ_ref).unwrap_or_default();
            (sel, typ, imp)
        };
        methods.push(ObjcMethod::new(selector, type_enc, imp, is_class_method));
        offset += entry_size;
    }
    Ok(methods)
}

// ---------------------------------------------------------------------------
// MachoObjc — top-level aggregator
// ---------------------------------------------------------------------------

/// Complete Objective-C runtime analysis of a Mach-O binary.
#[derive(Debug, Default)]
pub struct MachoObjc {
    pub classes: Vec<ObjcClass>,
    pub categories: Vec<ObjcCategory>,
    pub protocols: Vec<ObjcProtocol>,
    pub selectors: Vec<ObjcSelector>,
    class_name_index: HashMap<String, usize>,
    protocol_name_index: HashMap<String, usize>,
}

impl MachoObjc {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a class.
    pub fn add_class(&mut self, cls: ObjcClass) {
        let idx = self.classes.len();
        self.class_name_index.insert(cls.name.clone(), idx);
        self.classes.push(cls);
    }

    /// Register a category.
    pub fn add_category(&mut self, cat: ObjcCategory) {
        self.categories.push(cat);
    }

    /// Register a protocol.
    pub fn add_protocol(&mut self, proto: ObjcProtocol) {
        let idx = self.protocols.len();
        self.protocol_name_index.insert(proto.name.clone(), idx);
        self.protocols.push(proto);
    }

    /// Register a selector.
    pub fn add_selector(&mut self, sel: ObjcSelector) {
        self.selectors.push(sel);
    }

    /// Look up a class by name.
    #[must_use] 
    pub fn find_class(&self, name: &str) -> Option<&ObjcClass> {
        self.class_name_index.get(name).map(|&i| &self.classes[i])
    }

    /// Look up a protocol by name.
    #[must_use] 
    pub fn find_protocol(&self, name: &str) -> Option<&ObjcProtocol> {
        self.protocol_name_index
            .get(name)
            .map(|&i| &self.protocols[i])
    }

    /// All classes that inherit from `superclass_name`.
    #[must_use] 
    pub fn subclasses_of(&self, superclass_name: &str) -> Vec<&ObjcClass> {
        self.classes
            .iter()
            .filter(|c| c.superclass_name == superclass_name)
            .collect()
    }

    /// Classes conforming to `protocol_name`.
    #[must_use] 
    pub fn classes_conforming_to(&self, protocol_name: &str) -> Vec<&ObjcClass> {
        self.classes
            .iter()
            .filter(|c| c.conforms_to(protocol_name))
            .collect()
    }

    /// All unique selector strings.
    #[must_use] 
    pub fn unique_selectors(&self) -> Vec<&str> {
        let mut seen = std::collections::HashSet::new();
        self.selectors
            .iter()
            .filter(|s| seen.insert(s.name.as_str()))
            .map(|s| s.name.as_str())
            .collect()
    }

    /// Total number of methods across all classes.
    #[must_use] 
    pub fn total_method_count(&self) -> usize {
        self.classes
            .iter()
            .map(|c| c.instance_methods.len() + c.class_methods.len())
            .sum()
    }

    /// `true` if any class appears to contain Swift-bridged code.
    #[must_use] 
    pub fn has_swift_classes(&self) -> bool {
        self.classes.iter().any(ObjcClass::is_swift)
    }
}

// ---------------------------------------------------------------------------
// ObjcXrefGraph — cross-reference graph
// ---------------------------------------------------------------------------

/// A directed edge in the `ObjC` class/protocol graph.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjcXref {
    pub from: String,
    pub to: String,
    pub kind: XrefKind,
}

/// Kind of `ObjC` cross-reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XrefKind {
    /// Class inherits from superclass.
    Inherits,
    /// Class conforms to protocol.
    Conforms,
    /// Category extends class.
    Extends,
    /// Protocol inherits from protocol.
    ProtoInherits,
}

impl XrefKind {
    #[must_use] 
    pub const fn label(self) -> &'static str {
        match self {
            Self::Inherits => "inherits",
            Self::Conforms => "conforms_to",
            Self::Extends => "extends",
            Self::ProtoInherits => "proto_inherits",
        }
    }
}

/// Cross-reference graph for `ObjC` class hierarchy.
#[derive(Debug, Default)]
pub struct ObjcXrefGraph {
    pub edges: Vec<ObjcXref>,
}

impl ObjcXrefGraph {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    /// Build from a `MachoObjc` analysis.
    #[must_use] 
    pub fn build(objc: &MachoObjc) -> Self {
        let mut g = Self::new();
        for cls in &objc.classes {
            if !cls.superclass_name.is_empty() {
                g.edges.push(ObjcXref {
                    from: cls.name.clone(),
                    to: cls.superclass_name.clone(),
                    kind: XrefKind::Inherits,
                });
            }
            for proto in &cls.protocols {
                g.edges.push(ObjcXref {
                    from: cls.name.clone(),
                    to: proto.clone(),
                    kind: XrefKind::Conforms,
                });
            }
        }
        for cat in &objc.categories {
            g.edges.push(ObjcXref {
                from: cat.name.clone(),
                to: cat.class_name.clone(),
                kind: XrefKind::Extends,
            });
        }
        for proto in &objc.protocols {
            for base in &proto.base_protocols {
                g.edges.push(ObjcXref {
                    from: proto.name.clone(),
                    to: base.clone(),
                    kind: XrefKind::ProtoInherits,
                });
            }
        }
        g
    }

    /// Find all edges from a given node.
    #[must_use] 
    pub fn edges_from(&self, name: &str) -> Vec<&ObjcXref> {
        self.edges.iter().filter(|e| e.from == name).collect()
    }

    /// Find all edges to a given node.
    #[must_use] 
    pub fn edges_to(&self, name: &str) -> Vec<&ObjcXref> {
        self.edges.iter().filter(|e| e.to == name).collect()
    }

    /// All classes that directly inherit from `name`.
    #[must_use] 
    pub fn direct_subclasses(&self, name: &str) -> Vec<&str> {
        self.edges
            .iter()
            .filter(|e| e.to == name && matches!(e.kind, XrefKind::Inherits))
            .map(|e| e.from.as_str())
            .collect()
    }

    #[must_use] 
    pub const fn edge_count(&self) -> usize {
        self.edges.len()
    }
}

// ---------------------------------------------------------------------------
// ObjcMethodIndex — fast method-name lookup across all classes
// ---------------------------------------------------------------------------

/// An entry in the method index.
#[derive(Debug, Clone)]
pub struct MethodIndexEntry {
    pub class_name: String,
    pub selector: String,
    pub imp: u64,
    pub is_class_method: bool,
}

/// Fast cross-class method lookup index.
#[derive(Debug, Default)]
pub struct ObjcMethodIndex {
    entries: Vec<MethodIndexEntry>,
    selector_map: HashMap<String, Vec<usize>>,
    imp_map: HashMap<u64, usize>,
}

impl ObjcMethodIndex {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    /// Build from a `MachoObjc`.
    #[must_use] 
    pub fn build(objc: &MachoObjc) -> Self {
        let mut idx = Self::new();
        for cls in &objc.classes {
            for m in cls.instance_methods.iter().chain(cls.class_methods.iter()) {
                idx.add(
                    cls.name.clone(),
                    m.selector.clone(),
                    m.imp,
                    m.is_class_method,
                );
            }
        }
        idx
    }

    pub fn add(&mut self, class_name: String, selector: String, imp: u64, is_class: bool) {
        let pos = self.entries.len();
        self.selector_map
            .entry(selector.clone())
            .or_default()
            .push(pos);
        if imp != 0 {
            self.imp_map.insert(imp, pos);
        }
        self.entries.push(MethodIndexEntry {
            class_name,
            selector,
            imp,
            is_class_method: is_class,
        });
    }

    /// All methods with a given selector name.
    #[must_use] 
    pub fn find_by_selector(&self, selector: &str) -> Vec<&MethodIndexEntry> {
        self.selector_map.get(selector).map_or_else(std::vec::Vec::new, |idxs| idxs.iter().map(|&i| &self.entries[i]).collect())
    }

    /// Look up a method by its implementation address.
    #[must_use] 
    pub fn find_by_imp(&self, imp: u64) -> Option<&MethodIndexEntry> {
        self.imp_map.get(&imp).map(|&i| &self.entries[i])
    }

    #[must_use] 
    pub const fn total_method_count(&self) -> usize {
        self.entries.len()
    }

    /// Unique selector count.
    #[must_use] 
    pub fn unique_selector_count(&self) -> usize {
        self.selector_map.len()
    }
}

// ---------------------------------------------------------------------------
// ObjcStringPool — deduplicating string pool for selector/type encoding storage
// ---------------------------------------------------------------------------

/// Deduplicating string pool.
#[derive(Debug, Default)]
pub struct ObjcStringPool {
    strings: Vec<String>,
    index: HashMap<String, u32>,
}

impl ObjcStringPool {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    /// Intern a string, returning its stable index.
    pub fn intern(&mut self, s: impl Into<String>) -> u32 {
        let s = s.into();
        if let Some(&idx) = self.index.get(&s) {
            return idx;
        }
        let idx = self.strings.len() as u32;
        self.index.insert(s.clone(), idx);
        self.strings.push(s);
        idx
    }

    /// Retrieve interned string by index.
    #[must_use] 
    pub fn get(&self, idx: u32) -> Option<&str> {
        self.strings.get(idx as usize).map(std::string::String::as_str)
    }

    #[must_use] 
    pub const fn len(&self) -> usize {
        self.strings.len()
    }
    #[must_use] 
    pub const fn is_empty(&self) -> bool {
        self.strings.is_empty()
    }
}

// ---------------------------------------------------------------------------
// ObjcRuntimeAnalysis — runtime-level ObjC analysis
// ---------------------------------------------------------------------------

/// Result of analysing `ObjC` runtime metadata for security-relevant patterns.
#[derive(Debug, Clone, Default)]
pub struct ObjcRuntimeAnalysis {
    /// Classes that override `+load` (executed at dylib load time).
    pub load_method_classes: Vec<String>,
    /// Classes that override `+initialize`.
    pub initialize_method_classes: Vec<String>,
    /// Methods that perform method swizzling (`method_exchangeImplementations`).
    pub swizzling_classes: Vec<String>,
    /// Classes that implement `NSCoding` (serialization).
    pub nscoding_classes: Vec<String>,
    /// Classes that implement `NSURLSessionDelegate` (network).
    pub network_delegate_classes: Vec<String>,
    pub swift_class_count: usize,
    pub pure_objc_class_count: usize,
}

impl ObjcRuntimeAnalysis {
    /// Build from a `MachoObjc` analysis.
    #[must_use] 
    pub fn build(objc: &MachoObjc) -> Self {
        let mut result = Self::default();
        for cls in &objc.classes {
            if cls.is_swift() {
                result.swift_class_count += 1;
            } else {
                result.pure_objc_class_count += 1;
            }
            // Check for +load
            if cls.class_methods.iter().any(|m| m.selector == "load") {
                result.load_method_classes.push(cls.name.clone());
            }
            // Check for +initialize
            if cls.class_methods.iter().any(|m| m.selector == "initialize") {
                result.initialize_method_classes.push(cls.name.clone());
            }
            // NSCoding conformance
            if cls.conforms_to("NSCoding") {
                result.nscoding_classes.push(cls.name.clone());
            }
            // Network delegate
            if cls.conforms_to("NSURLSessionDelegate") || cls.conforms_to("NSURLConnectionDelegate")
            {
                result.network_delegate_classes.push(cls.name.clone());
            }
        }
        result
    }

    /// `true` if any class uses the `+load` hook (runs before main).
    #[must_use] 
    pub const fn has_load_hooks(&self) -> bool {
        !self.load_method_classes.is_empty()
    }
}

// ---------------------------------------------------------------------------
// ObjcTypeEncodingParser — parse ObjC type encoding strings
// ---------------------------------------------------------------------------

/// One component of a parsed type encoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TypeEncodingComponent {
    Void,
    Bool,
    Char,
    UChar,
    Short,
    UShort,
    Int,
    UInt,
    Long,
    ULong,
    LongLong,
    ULongLong,
    Float,
    Double,
    Object,
    Class,
    Selector,
    Unknown(char),
}

impl TypeEncodingComponent {
    #[must_use] 
    pub const fn from_char(c: char) -> Self {
        match c {
            'v' => Self::Void,
            'B' => Self::Bool,
            'c' => Self::Char,
            'C' => Self::UChar,
            's' => Self::Short,
            'S' => Self::UShort,
            'i' => Self::Int,
            'I' => Self::UInt,
            'l' => Self::Long,
            'L' => Self::ULong,
            'q' => Self::LongLong,
            'Q' => Self::ULongLong,
            'f' => Self::Float,
            'd' => Self::Double,
            '@' => Self::Object,
            '#' => Self::Class,
            ':' => Self::Selector,
            c => Self::Unknown(c),
        }
    }

    #[must_use] 
    pub const fn is_primitive(&self) -> bool {
        !matches!(
            self,
            Self::Object | Self::Class | Self::Selector | Self::Unknown(_)
        )
    }
}

/// Parse a simplified `ObjC` type encoding string.
pub fn parse_type_encoding(enc: &str) -> Vec<TypeEncodingComponent> {
    enc.chars()
        .filter(|c| c.is_alphabetic() || *c == '@' || *c == '#' || *c == ':')
        .map(TypeEncodingComponent::from_char)
        .collect()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ---- ObjcSelector ----

    #[test]
    fn test_selector_argument_count_none() {
        let s = ObjcSelector::new("description", 0);
        assert_eq!(s.argument_count(), 0);
    }

    #[test]
    fn test_selector_argument_count_one() {
        let s = ObjcSelector::new("setFrame:", 0);
        assert_eq!(s.argument_count(), 1);
    }

    #[test]
    fn test_selector_argument_count_many() {
        let s = ObjcSelector::new("insertObject:atIndex:", 0);
        assert_eq!(s.argument_count(), 2);
    }

    #[test]
    fn test_selector_is_getter() {
        let s = ObjcSelector::new("count", 0);
        assert!(s.is_likely_getter());
    }

    #[test]
    fn test_selector_is_not_getter_uppercase() {
        let s = ObjcSelector::new("NSLog", 0);
        assert!(!s.is_likely_getter());
    }

    #[test]
    fn test_selector_is_setter() {
        let s = ObjcSelector::new("setCount:", 0);
        assert!(s.is_likely_setter());
    }

    #[test]
    fn test_selector_is_not_setter_no_colon() {
        let s = ObjcSelector::new("setCount", 0);
        assert!(!s.is_likely_setter());
    }

    // ---- ObjcMethod ----

    #[test]
    fn test_method_returns_void() {
        let m = ObjcMethod::new("dealloc", "v16@0:8", 0x1000, false);
        assert!(m.returns_void());
    }

    #[test]
    fn test_method_returns_non_void() {
        let m = ObjcMethod::new("count", "I16@0:8", 0x1000, false);
        assert!(!m.returns_void());
    }

    #[test]
    fn test_method_prefix_instance() {
        let m = ObjcMethod::new("init", "v16@0:8", 0, false);
        assert_eq!(m.prefix(), '-');
    }

    #[test]
    fn test_method_prefix_class() {
        let m = ObjcMethod::new("alloc", "@16@0:8", 0, true);
        assert_eq!(m.prefix(), '+');
    }

    #[test]
    fn test_method_format_with_class() {
        let m = ObjcMethod::new("initWithFrame:", "v24@0:8{CGRect=...}16", 0, false);
        assert_eq!(m.format_with_class("UIView"), "-[UIView initWithFrame:]");
    }

    // ---- ObjcIvar ----

    #[test]
    fn test_ivar_alignment_bytes() {
        let iv = ObjcIvar::new("_count", "I", 8, 4, 2); // 1 << 2 = 4
        assert_eq!(iv.alignment_bytes(), 4);
    }

    #[test]
    fn test_ivar_alignment_bytes_8() {
        let iv = ObjcIvar::new("_ptr", "^v", 16, 8, 3); // 1 << 3 = 8
        assert_eq!(iv.alignment_bytes(), 8);
    }

    // ---- ObjcProperty ----

    #[test]
    fn test_property_readonly() {
        let p = ObjcProperty::from_attribute_string("count", "Ti,R,N,Vcount");
        assert!(p.is_readonly);
        assert!(p.is_nonatomic);
    }

    #[test]
    fn test_property_copy() {
        let p = ObjcProperty::from_attribute_string("name", "T@\"NSString\",C,N,Vname");
        assert!(p.is_copy);
    }

    #[test]
    fn test_property_weak() {
        let p = ObjcProperty::from_attribute_string("delegate", "T@,W,N,Vdelegate");
        assert!(p.is_weak);
    }

    #[test]
    fn test_property_retain() {
        let p = ObjcProperty::from_attribute_string("view", "T@\"UIView\",&,N,Vview");
        assert!(p.is_retain);
    }

    // ---- ObjcClass ----

    #[test]
    fn test_class_is_root() {
        let c = ObjcClass::new("NSObject", 0x1000);
        assert!(c.is_root_class());
    }

    #[test]
    fn test_class_not_root_has_super() {
        let mut c = ObjcClass::new("UIView", 0x2000);
        c.superclass_name = "UIResponder".to_string();
        assert!(!c.is_root_class());
    }

    #[test]
    fn test_class_find_method_present() {
        let mut c = ObjcClass::new("MyClass", 0x3000);
        c.instance_methods
            .push(ObjcMethod::new("doSomething", "v16@0:8", 0x4000, false));
        assert!(c.find_method("doSomething").is_some());
    }

    #[test]
    fn test_class_find_method_absent() {
        let c = ObjcClass::new("MyClass", 0x3000);
        assert!(c.find_method("nonexistent").is_none());
    }

    #[test]
    fn test_class_conforms_to() {
        let mut c = ObjcClass::new("Foo", 0x1000);
        c.protocols.push("NSCopying".to_string());
        assert!(c.conforms_to("NSCopying"));
        assert!(!c.conforms_to("NSCoding"));
    }

    #[test]
    fn test_class_all_selector_names() {
        let mut c = ObjcClass::new("Foo", 0x1000);
        c.instance_methods
            .push(ObjcMethod::new("bar", "v16@0:8", 0, false));
        c.class_methods
            .push(ObjcMethod::new("baz", "v16@0:8", 0, true));
        let names = c.all_selector_names();
        assert!(names.contains(&"bar"));
        assert!(names.contains(&"baz"));
    }

    #[test]
    fn test_class_flags_swift() {
        let f = ObjcClassFlags(0x08);
        assert!(f.is_swift());
    }

    #[test]
    fn test_class_flags_root() {
        let f = ObjcClassFlags(0x01);
        assert!(f.is_root());
    }

    #[test]
    fn test_class_flags_cxx_structors() {
        let f = ObjcClassFlags(0x04);
        assert!(f.has_cxx_structors());
    }

    // ---- ObjcProtocol ----

    #[test]
    fn test_protocol_method_counts() {
        let mut proto = ObjcProtocol::new("MyProto", 0x5000);
        proto
            .instance_methods
            .push(ObjcMethod::new("req", "v16@0:8", 0, false));
        proto
            .optional_instance_methods
            .push(ObjcMethod::new("opt", "v16@0:8", 0, false));
        assert_eq!(proto.required_method_count(), 1);
        assert_eq!(proto.optional_method_count(), 1);
    }

    // ---- ObjcCategory ----

    #[test]
    fn test_category_adds_methods_true() {
        let mut cat = ObjcCategory::new("Additions", "NSString", 0x6000);
        cat.instance_methods
            .push(ObjcMethod::new("trimmed", "@16@0:8", 0x7000, false));
        assert!(cat.adds_methods());
    }

    #[test]
    fn test_category_adds_methods_false() {
        let cat = ObjcCategory::new("Additions", "NSString", 0x6000);
        assert!(!cat.adds_methods());
    }

    // ---- MachoObjc ----

    #[test]
    fn test_macho_objc_add_and_find_class() {
        let mut mo = MachoObjc::new();
        mo.add_class(ObjcClass::new("UIViewController", 0x1000));
        assert!(mo.find_class("UIViewController").is_some());
        assert!(mo.find_class("NSObject").is_none());
    }

    #[test]
    fn test_macho_objc_find_protocol() {
        let mut mo = MachoObjc::new();
        mo.add_protocol(ObjcProtocol::new("UITableViewDelegate", 0x2000));
        assert!(mo.find_protocol("UITableViewDelegate").is_some());
    }

    #[test]
    fn test_macho_objc_subclasses_of() {
        let mut mo = MachoObjc::new();
        let mut c1 = ObjcClass::new("UIView", 0x1000);
        c1.superclass_name = "UIResponder".to_string();
        let mut c2 = ObjcClass::new("UIControl", 0x2000);
        c2.superclass_name = "UIResponder".to_string();
        let c3 = ObjcClass::new("UIResponder", 0x3000);
        mo.add_class(c1);
        mo.add_class(c2);
        mo.add_class(c3);
        assert_eq!(mo.subclasses_of("UIResponder").len(), 2);
    }

    #[test]
    fn test_macho_objc_classes_conforming_to() {
        let mut mo = MachoObjc::new();
        let mut c = ObjcClass::new("MyVC", 0x1000);
        c.protocols.push("UITableViewDataSource".to_string());
        mo.add_class(c);
        assert_eq!(mo.classes_conforming_to("UITableViewDataSource").len(), 1);
        assert_eq!(mo.classes_conforming_to("NSCopying").len(), 0);
    }

    #[test]
    fn test_macho_objc_total_method_count() {
        let mut mo = MachoObjc::new();
        let mut c = ObjcClass::new("Foo", 0x1000);
        c.instance_methods.push(ObjcMethod::new("a", "v", 0, false));
        c.instance_methods.push(ObjcMethod::new("b", "v", 0, false));
        c.class_methods.push(ObjcMethod::new("c", "v", 0, true));
        mo.add_class(c);
        assert_eq!(mo.total_method_count(), 3);
    }

    #[test]
    fn test_macho_objc_has_swift_classes() {
        let mut mo = MachoObjc::new();
        let mut c = ObjcClass::new("SwiftClass", 0x1000);
        c.flags = ObjcClassFlags(ObjcClassFlags::IS_SWIFT);
        mo.add_class(c);
        assert!(mo.has_swift_classes());
    }

    #[test]
    fn test_macho_objc_unique_selectors() {
        let mut mo = MachoObjc::new();
        mo.add_selector(ObjcSelector::new("init", 0x1000));
        mo.add_selector(ObjcSelector::new("init", 0x1008)); // duplicate
        mo.add_selector(ObjcSelector::new("dealloc", 0x1010));
        let unique = mo.unique_selectors();
        assert_eq!(unique.len(), 2);
    }

    #[test]
    fn test_parse_method_list_empty() {
        // 8 bytes header: flags=0, count=0
        let data = [0u8; 8];
        let methods = parse_method_list(&data, false, &|_| None).unwrap();
        assert!(methods.is_empty());
    }

    #[test]
    fn test_parse_method_list_truncated() {
        let data = [0u8; 4]; // only 4 bytes
        assert!(matches!(
            parse_method_list(&data, false, &|_| None),
            Err(ObjcError::TruncatedData { .. })
        ));
    }

    #[test]
    fn test_parse_method_list_too_many() {
        let mut data = vec![0u8; 8];
        let huge: u32 = 100_000;
        data[4..8].copy_from_slice(&huge.to_le_bytes());
        assert!(matches!(
            parse_method_list(&data, false, &|_| None),
            Err(ObjcError::TooManyMethods(_))
        ));
    }

    #[test]
    fn test_objc_error_display() {
        let e = ObjcError::TooManyClasses(99999);
        assert!(e.to_string().contains("99999"));
        let e2 = ObjcError::InvalidPointer(0xdead_beef);
        assert!(e2.to_string().contains("deadbeef"));
    }

    #[test]
    fn test_macho_objc_add_category() {
        let mut mo = MachoObjc::new();
        mo.add_category(ObjcCategory::new("Extensions", "NSString", 0x9000));
        assert_eq!(mo.categories.len(), 1);
    }

    // ---- ObjcXrefGraph ----

    #[test]
    fn test_xref_graph_inherits_edge() {
        let mut mo = MachoObjc::new();
        let mut c = ObjcClass::new("Child", 0x1000);
        c.superclass_name = "Parent".into();
        mo.add_class(c);
        let g = ObjcXrefGraph::build(&mo);
        let edges = g.edges_from("Child");
        assert_eq!(edges.len(), 1);
        assert_eq!(edges[0].kind, XrefKind::Inherits);
    }

    #[test]
    fn test_xref_graph_conforms_edge() {
        let mut mo = MachoObjc::new();
        let mut c = ObjcClass::new("Foo", 0x1000);
        c.protocols.push("NSCopying".into());
        mo.add_class(c);
        let g = ObjcXrefGraph::build(&mo);
        let edges = g.edges_from("Foo");
        assert!(edges.iter().any(|e| matches!(e.kind, XrefKind::Conforms)));
    }

    #[test]
    fn test_xref_graph_extends_edge() {
        let mut mo = MachoObjc::new();
        mo.add_category(ObjcCategory::new("Extras", "NSString", 0x5000));
        let g = ObjcXrefGraph::build(&mo);
        let edges = g.edges_from("Extras");
        assert_eq!(edges[0].kind, XrefKind::Extends);
    }

    #[test]
    fn test_xref_graph_edges_to() {
        let mut mo = MachoObjc::new();
        let mut c1 = ObjcClass::new("A", 0x1000);
        c1.superclass_name = "Base".into();
        let mut c2 = ObjcClass::new("B", 0x2000);
        c2.superclass_name = "Base".into();
        mo.add_class(c1);
        mo.add_class(c2);
        let g = ObjcXrefGraph::build(&mo);
        assert_eq!(g.direct_subclasses("Base").len(), 2);
    }

    #[test]
    fn test_xref_kind_labels() {
        assert_eq!(XrefKind::Inherits.label(), "inherits");
        assert_eq!(XrefKind::Conforms.label(), "conforms_to");
        assert_eq!(XrefKind::Extends.label(), "extends");
        assert_eq!(XrefKind::ProtoInherits.label(), "proto_inherits");
    }

    // ---- ObjcMethodIndex ----

    #[test]
    fn test_method_index_find_by_selector() {
        let mut idx = ObjcMethodIndex::new();
        idx.add("Foo".into(), "doThing".into(), 0x1000, false);
        idx.add("Bar".into(), "doThing".into(), 0x2000, false);
        assert_eq!(idx.find_by_selector("doThing").len(), 2);
    }

    #[test]
    fn test_method_index_find_by_imp() {
        let mut idx = ObjcMethodIndex::new();
        idx.add("Foo".into(), "init".into(), 0x3000, false);
        assert!(idx.find_by_imp(0x3000).is_some());
        assert!(idx.find_by_imp(0x9999).is_none());
    }

    #[test]
    fn test_method_index_unique_selectors() {
        let mut idx = ObjcMethodIndex::new();
        idx.add("A".into(), "x".into(), 0x100, false);
        idx.add("B".into(), "x".into(), 0x200, false);
        idx.add("C".into(), "y".into(), 0x300, false);
        assert_eq!(idx.unique_selector_count(), 2);
        assert_eq!(idx.total_method_count(), 3);
    }

    #[test]
    fn test_method_index_build_from_objc() {
        let mut mo = MachoObjc::new();
        let mut c = ObjcClass::new("MyClass", 0x1000);
        c.instance_methods
            .push(ObjcMethod::new("foo", "v", 0x4000, false));
        mo.add_class(c);
        let idx = ObjcMethodIndex::build(&mo);
        assert_eq!(idx.total_method_count(), 1);
    }

    // ---- ObjcStringPool ----

    #[test]
    fn test_string_pool_intern_dedup() {
        let mut pool = ObjcStringPool::new();
        let a = pool.intern("hello");
        let b = pool.intern("hello");
        assert_eq!(a, b);
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn test_string_pool_intern_different() {
        let mut pool = ObjcStringPool::new();
        let a = pool.intern("hello");
        let b = pool.intern("world");
        assert_ne!(a, b);
        assert_eq!(pool.len(), 2);
    }

    #[test]
    fn test_string_pool_get() {
        let mut pool = ObjcStringPool::new();
        let idx = pool.intern("selector");
        assert_eq!(pool.get(idx), Some("selector"));
        assert!(pool.get(99).is_none());
    }

    #[test]
    fn test_string_pool_is_empty() {
        let pool = ObjcStringPool::new();
        assert!(pool.is_empty());
    }
}

// ---------------------------------------------------------------------------
// ObjcPropertyEncoder — encode/decode ObjC property attributes
// ---------------------------------------------------------------------------

/// Encodes property attributes into an `ObjC` property attribute string.
pub struct ObjcPropertyEncoder;

impl ObjcPropertyEncoder {
    /// Build attribute string from components.
    #[must_use] 
    pub fn encode(
        type_encoding: &str,
        is_readonly: bool,
        is_copy: bool,
        is_retain: bool,
        is_nonatomic: bool,
        is_weak: bool,
        ivar_name: Option<&str>,
    ) -> String {
        let mut parts = vec![format!("T{}", type_encoding)];
        if is_readonly {
            parts.push("R".into());
        }
        if is_copy {
            parts.push("C".into());
        }
        if is_retain {
            parts.push("&".into());
        }
        if is_nonatomic {
            parts.push("N".into());
        }
        if is_weak {
            parts.push("W".into());
        }
        if let Some(name) = ivar_name {
            parts.push(format!("V{name}"));
        }
        parts.join(",")
    }

    /// Extract the ivar name from an attribute string (after `V`).
    #[must_use] 
    pub fn ivar_name(attrs: &str) -> Option<&str> {
        attrs
            .split(',')
            .find(|p| p.starts_with('V'))
            .map(|p| &p[1..])
    }

    /// Extract the type encoding from an attribute string (after `T`).
    #[must_use] 
    pub fn type_encoding(attrs: &str) -> Option<&str> {
        attrs
            .split(',')
            .find(|p| p.starts_with('T'))
            .map(|p| &p[1..])
    }
}

// ---------------------------------------------------------------------------
// ObjcSelectorRef — selector reference entry
// ---------------------------------------------------------------------------

/// A selector reference from `__objc_selrefs` section.
#[derive(Debug, Clone)]
pub struct ObjcSelectorRef {
    /// VA of the selector reference pointer.
    pub ref_va: u64,
    /// VA of the selector string.
    pub str_va: u64,
    /// Resolved selector name.
    pub name: String,
}

impl ObjcSelectorRef {
    pub fn new(ref_va: u64, str_va: u64, name: impl Into<String>) -> Self {
        Self {
            ref_va,
            str_va,
            name: name.into(),
        }
    }
}

// ---------------------------------------------------------------------------
// ObjcClassRef — class reference entry
// ---------------------------------------------------------------------------

/// A class reference from `__objc_classrefs` section.
#[derive(Debug, Clone)]
pub struct ObjcClassRef {
    pub ref_va: u64,
    pub class_va: u64,
    pub class_name: String,
}

impl ObjcClassRef {
    pub fn new(ref_va: u64, class_va: u64, class_name: impl Into<String>) -> Self {
        Self {
            ref_va,
            class_va,
            class_name: class_name.into(),
        }
    }
}

// ---------------------------------------------------------------------------
// ObjcSectionInfo — summary of ObjC sections found in the binary
// ---------------------------------------------------------------------------

/// Summary of ObjC-related sections present in a Mach-O binary.
#[derive(Debug, Clone, Default)]
pub struct ObjcSectionInfo {
    pub has_classlist: bool,
    pub has_catlist: bool,
    pub has_protolist: bool,
    pub has_selrefs: bool,
    pub has_classrefs: bool,
    pub has_superrefs: bool,
    pub has_ivar_offsets: bool,
    pub has_relative_method_lists: bool,
}

impl ObjcSectionInfo {
    #[must_use] 
    pub const fn is_objc_binary(&self) -> bool {
        self.has_classlist || self.has_catlist || self.has_protolist
    }

    #[must_use] 
    pub const fn is_swift_objc_bridge(&self) -> bool {
        self.has_relative_method_lists && self.has_classlist
    }
}
// ---------------------------------------------------------------------------
// ObjcTaggedPointerInfo — tagged pointer analysis
// ---------------------------------------------------------------------------

/// Information about Objective-C tagged pointers.
#[derive(Debug, Clone)]
pub struct ObjcTaggedPointerInfo {
    pub tag: u8,
    pub payload: u64,
    pub class_name: &'static str,
}

/// Decode a tagged pointer.
#[must_use] 
pub const fn decode_tagged_pointer(ptr: u64, is_arm64: bool) -> Option<ObjcTaggedPointerInfo> {
    if is_arm64 {
        if ptr & 0x8000_0000_0000_0000 == 0 {
            return None;
        }
        let tag = ((ptr >> 60) & 0x7) as u8;
        let payload = ptr & 0x0FFF_FFFF_FFFF_FFFF;
        let class_name = match tag {
            0 => "NSAtom",
            1 => "NSNumber<int>",
            2 => "NSNumber<float>",
            3 => "NSDate",
            4 => "NSString",
            6 => "NSIndexPath",
            _ => "Unknown",
        };
        Some(ObjcTaggedPointerInfo {
            tag,
            payload,
            class_name,
        })
    } else {
        if ptr & 0x1 == 0 {
            return None;
        }
        let tag = ((ptr >> 1) & 0xf) as u8;
        let payload = (ptr >> 4) & 0x0FFF_FFFF;
        Some(ObjcTaggedPointerInfo {
            tag,
            payload,
            class_name: "NSObject",
        })
    }
}

// ---------------------------------------------------------------------------
// ObjcSwiftMangle — Swift name mangling utilities
// ---------------------------------------------------------------------------

/// Swift name mangling detection and demangle hint.
#[must_use] 
pub fn is_swift_mangled(name: &str) -> bool {
    name.starts_with("_T")
        || name.starts_with("_$s")
        || name.starts_with("$s")
        || name.starts_with("$S")
}

/// Strip the Swift mangling prefix to get a rough class name.
#[must_use] 
pub fn swift_class_hint(mangled: &str) -> &str {
    mangled.strip_prefix("_$s").unwrap_or_else(|| if let Some(__stripped) = mangled.strip_prefix("$s") {
        __stripped
    } else {
        mangled
    })
}

// ---------------------------------------------------------------------------
// ObjcInheritanceChain — iterate the class hierarchy
// ---------------------------------------------------------------------------

/// Walk the inheritance chain for a class.
#[must_use] 
pub fn class_inheritance_chain<'a>(objc: &'a MachoObjc, class_name: &'a str) -> Vec<&'a str> {
    let mut chain = Vec::new();
    let mut current = class_name;
    let mut depth = 0;
    while depth < 64 {
        chain.push(current);
        if let Some(cls) = objc.find_class(current) {
            if cls.superclass_name.is_empty() {
                break;
            }
            current = cls.superclass_name.as_str();
        } else {
            break;
        }
        depth += 1;
    }
    chain
}

/// Count the depth of the inheritance chain.
#[must_use] 
pub fn inheritance_depth(objc: &MachoObjc, class_name: &str) -> usize {
    class_inheritance_chain(objc, class_name)
        .len()
        .saturating_sub(1)
}

// ---------------------------------------------------------------------------
// ObjcPropertySummary — property statistics
// ---------------------------------------------------------------------------

/// Summary statistics about `ObjC` properties.
#[derive(Debug, Clone, Default)]
pub struct ObjcPropertySummary {
    pub total: usize,
    pub readonly_count: usize,
    pub copy_count: usize,
    pub weak_count: usize,
    pub retain_count: usize,
    pub nonatomic_count: usize,
}

impl ObjcPropertySummary {
    #[must_use] 
    pub fn from_class(cls: &ObjcClass) -> Self {
        let mut s = Self {
            total: cls.properties.len(),
            ..Default::default()
        };
        for p in &cls.properties {
            if p.is_readonly {
                s.readonly_count += 1;
            }
            if p.is_copy {
                s.copy_count += 1;
            }
            if p.is_weak {
                s.weak_count += 1;
            }
            if p.is_retain {
                s.retain_count += 1;
            }
            if p.is_nonatomic {
                s.nonatomic_count += 1;
            }
        }
        s
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
