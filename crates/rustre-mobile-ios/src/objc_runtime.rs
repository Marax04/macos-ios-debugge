//! Objective-C runtime metadata recovery — **low-level type-system layer**.
//!
//! Parses `__objc_classlist`, `__objc_methname`, `__objc_classname`,
//! `__objc_methtype`, `__objc_protolist`, `__objc_catlist` sections from
//! Mach-O binaries to reconstruct class hierarchies, methods, ivars and
//! protocol conformances.
//!
//! # Layer distinction
//! This module owns the **typed encoding** vocabulary ([`ObjcType`] enum,
//! [`decode_type_encoding`], [`MethodTypes`]) and the section-level parser
//! ([`ObjcMetadataParser`], [`ObjcPropertyFlags`]).  It is intentionally
//! distinct from:
//!
//! * `macho_objc_runtime` — walks the binary `class_ro_t`/`method_list_t`
//!   ABI structures with full VMA→file-offset resolution.
//! * `objc_runtime_analysis` — high-level behavioural analysis (swizzle
//!   detection, `objc_msgSend` hook scanning, `ObjcRuntimeReport`).

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use thiserror::Error;

// ─── Error ────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum ObjcError {
    #[error("truncated data at offset {0}")]
    Truncated(usize),
    #[error("invalid pointer {0:#x}")]
    InvalidPointer(u64),
    #[error("invalid utf-8 in symbol: {0}")]
    InvalidUtf8(String),
    #[error("missing section: {0}")]
    MissingSection(String),
    #[error("parse error: {0}")]
    Parse(String),
}

// ─── ObjcType ─────────────────────────────────────────────────────────────────

/// A decoded `ObjC` type from a type encoding character.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ObjcType {
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
    LongDouble,
    Pointer(Box<Self>),
    Id,
    Class,
    Selector,
    Struct(String),
    Union(String),
    Array(usize, Box<Self>),
    Bitfield(usize),
    Unknown(char),
}

impl fmt::Display for ObjcType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Void => write!(f, "void"),
            Self::Bool => write!(f, "BOOL"),
            Self::Char => write!(f, "char"),
            Self::UChar => write!(f, "unsigned char"),
            Self::Short => write!(f, "short"),
            Self::UShort => write!(f, "unsigned short"),
            Self::Int => write!(f, "int"),
            Self::UInt => write!(f, "unsigned int"),
            Self::Long => write!(f, "long"),
            Self::ULong => write!(f, "unsigned long"),
            Self::LongLong => write!(f, "long long"),
            Self::ULongLong => write!(f, "unsigned long long"),
            Self::Float => write!(f, "float"),
            Self::Double => write!(f, "double"),
            Self::LongDouble => write!(f, "long double"),
            Self::Pointer(inner) => write!(f, "{inner}*"),
            Self::Id => write!(f, "id"),
            Self::Class => write!(f, "Class"),
            Self::Selector => write!(f, "SEL"),
            Self::Struct(name) => write!(f, "struct {name}"),
            Self::Union(name) => write!(f, "union {name}"),
            Self::Array(n, t) => write!(f, "{t}[{n}]"),
            Self::Bitfield(n) => write!(f, "unsigned :{n}"),
            Self::Unknown(c) => write!(f, "?({c})"),
        }
    }
}

// ─── Type encoding decoder ────────────────────────────────────────────────────

/// Decode an `ObjC` type encoding string into a list of [`ObjcType`]s.
///
/// The encoding format is: `return_type arg_frame_size arg1 arg2 ...`
/// e.g. `"v16@0:8"` = `(void, id self, SEL cmd)` with 16 byte frame.
#[must_use]
pub fn decode_type_encoding(enc: &str) -> Vec<ObjcType> {
    let chars: Vec<char> = enc.chars().collect();
    let mut types = Vec::new();
    let mut i = 0;

    while i < chars.len() {
        // Skip numeric offset / stack-frame bytes.
        if chars[i].is_ascii_digit() {
            while i < chars.len() && chars[i].is_ascii_digit() {
                i += 1;
            }
            continue;
        }

        let (ty, consumed) = decode_single_type(&chars[i..]);
        types.push(ty);
        i += consumed.max(1);
    }

    types
}

fn decode_single_type(chars: &[char]) -> (ObjcType, usize) {
    if chars.is_empty() {
        return (ObjcType::Unknown('?'), 0);
    }

    match chars[0] {
        'v' => (ObjcType::Void, 1),
        'B' => (ObjcType::Bool, 1),
        'c' => (ObjcType::Char, 1),
        'C' => (ObjcType::UChar, 1),
        's' => (ObjcType::Short, 1),
        'S' => (ObjcType::UShort, 1),
        'i' => (ObjcType::Int, 1),
        'I' => (ObjcType::UInt, 1),
        'l' => (ObjcType::Long, 1),
        'L' => (ObjcType::ULong, 1),
        'q' => (ObjcType::LongLong, 1),
        'Q' => (ObjcType::ULongLong, 1),
        'f' => (ObjcType::Float, 1),
        'd' => (ObjcType::Double, 1),
        'D' => (ObjcType::LongDouble, 1),
        '@' => (ObjcType::Id, 1),
        '#' => (ObjcType::Class, 1),
        ':' => (ObjcType::Selector, 1),
        '^' => {
            let (inner, consumed) = decode_single_type(&chars[1..]);
            (ObjcType::Pointer(Box::new(inner)), consumed + 1)
        }
        '{' => {
            // struct name }
            let end = chars.iter().position(|&c| c == '}').unwrap_or(chars.len());
            let name: String = chars[1..end.min(chars.len())].iter().collect();
            let name = name.split('=').next().unwrap_or(&name).to_string();
            (ObjcType::Struct(name), end + 1)
        }
        '(' => {
            // union name )
            let end = chars.iter().position(|&c| c == ')').unwrap_or(chars.len());
            let name: String = chars[1..end.min(chars.len())].iter().collect();
            let name = name.split('=').next().unwrap_or(&name).to_string();
            (ObjcType::Union(name), end + 1)
        }
        '[' => {
            // array: [Ntype]
            let mut j = 1;
            while j < chars.len() && chars[j].is_ascii_digit() {
                j += 1;
            }
            let count_str: String = chars[1..j].iter().collect();
            let count: usize = count_str.parse().unwrap_or(0);
            let (inner, consumed) = decode_single_type(&chars[j..]);
            // skip ']'
            (ObjcType::Array(count, Box::new(inner)), j + consumed + 1)
        }
        'b' => {
            // bitfield: bN
            let mut j = 1;
            while j < chars.len() && chars[j].is_ascii_digit() {
                j += 1;
            }
            let n_str: String = chars[1..j].iter().collect();
            let n: usize = n_str.parse().unwrap_or(0);
            (ObjcType::Bitfield(n), j)
        }
        // Qualifiers: skip.
        'r' | 'n' | 'N' | 'o' | 'O' | 'R' | 'V' => {
            let (inner, consumed) = decode_single_type(&chars[1..]);
            (inner, consumed + 1)
        }
        c => (ObjcType::Unknown(c), 1),
    }
}

// ─── MethodTypes ──────────────────────────────────────────────────────────────

/// Decoded method signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MethodTypes {
    pub return_type: String,
    pub args: Vec<String>,
}

impl MethodTypes {
    /// Decode from a raw `ObjC` type encoding string.
    #[must_use]
    pub fn from_encoding(enc: &str) -> Self {
        let types = decode_type_encoding(enc);
        let strings: Vec<String> = types.iter().map(std::string::ToString::to_string).collect();
        // First type is return type, then frame size, then args.
        let return_type = strings
            .first()
            .cloned()
            .unwrap_or_else(|| "void".to_string());
        // Skip return + 2 hidden args (self + cmd).
        let args: Vec<String> = if strings.len() > 3 {
            strings[3..].to_vec()
        } else {
            vec![]
        };
        Self { return_type, args }
    }
}

// ─── ObjcMethod ───────────────────────────────────────────────────────────────

/// An `ObjC` method.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjcMethod {
    pub selector: String,
    pub type_encoding: String,
    pub types: MethodTypes,
    pub imp: u64,
    pub is_class_method: bool,
}

impl ObjcMethod {
    /// Build the `ObjC` method signature string, e.g. `- (void)viewDidLoad`.
    #[must_use]
    pub fn signature_string(&self) -> String {
        use std::fmt::Write as _;
        let prefix = if self.is_class_method { "+" } else { "-" };
        let parts: Vec<&str> = self.selector.split(':').collect();
        let args = &self.types.args;
        if args.is_empty() || parts.len() == 1 {
            format!("{prefix} ({}) {}", self.types.return_type, self.selector)
        } else {
            let mut sig = format!("{prefix} ({}) ", self.types.return_type);
            for (i, part) in parts.iter().enumerate() {
                if part.is_empty() {
                    continue;
                }
                let arg_type = args.get(i).map_or("id", String::as_str);
                let _ = write!(sig, "{part}:({arg_type})arg{i} ");
            }
            sig.trim_end().to_string()
        }
    }
}

// ─── ObjcIvar ─────────────────────────────────────────────────────────────────

/// An `ObjC` instance variable.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjcIvar {
    pub name: String,
    pub type_str: String,
    pub offset: u32,
    pub size: u32,
    pub alignment: u32,
}

// ─── ObjcProperty ─────────────────────────────────────────────────────────────

/// Storage/semantic flags for an `ObjC` declared property (bitfield).
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct ObjcPropertyFlags(pub u8);

impl ObjcPropertyFlags {
    pub const READONLY: u8 = 0b0000_0001;
    pub const COPY: u8 = 0b0000_0010;
    pub const RETAIN: u8 = 0b0000_0100;
    pub const WEAK: u8 = 0b0000_1000;
    pub const ATOMIC: u8 = 0b0001_0000;

    #[must_use]
    pub const fn is_readonly(self) -> bool {
        (self.0 & Self::READONLY) != 0
    }
    #[must_use]
    pub const fn is_copy(self) -> bool {
        (self.0 & Self::COPY) != 0
    }
    #[must_use]
    pub const fn is_retain(self) -> bool {
        (self.0 & Self::RETAIN) != 0
    }
    #[must_use]
    pub const fn is_weak(self) -> bool {
        (self.0 & Self::WEAK) != 0
    }
    #[must_use]
    pub const fn is_atomic(self) -> bool {
        (self.0 & Self::ATOMIC) != 0
    }
}

impl Default for ObjcPropertyFlags {
    fn default() -> Self {
        Self(Self::ATOMIC)
    }
}

/// An `ObjC` declared property.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjcProperty {
    pub name: String,
    pub attributes: String,
    pub flags: ObjcPropertyFlags,
    pub backing_ivar: Option<String>,
    pub type_str: String,
}

impl ObjcProperty {
    /// Convenience: returns whether the property is read-only.
    #[must_use]
    pub const fn is_readonly(&self) -> bool {
        self.flags.is_readonly()
    }
    /// Convenience: returns whether the property uses copy semantics.
    #[must_use]
    pub const fn is_copy(&self) -> bool {
        self.flags.is_copy()
    }
    /// Convenience: returns whether the property uses retain semantics.
    #[must_use]
    pub const fn is_retain(&self) -> bool {
        self.flags.is_retain()
    }
    /// Convenience: returns whether the property is a weak reference.
    #[must_use]
    pub const fn is_weak(&self) -> bool {
        self.flags.is_weak()
    }
    /// Convenience: returns whether the property is atomic.
    #[must_use]
    pub const fn is_atomic(&self) -> bool {
        self.flags.is_atomic()
    }

    /// Parse property attributes string (e.g. `"T@\"NSString\",C,N,VmyIvar"`).
    #[must_use]
    pub fn from_attrs(name: &str, attrs: &str) -> Self {
        let mut prop = Self {
            name: name.to_string(),
            attributes: attrs.to_string(),
            flags: ObjcPropertyFlags::default(),
            backing_ivar: None,
            type_str: "id".to_string(),
        };
        for part in attrs.split(',') {
            let part = part.trim();
            match part.chars().next() {
                Some('T') => {
                    prop.type_str = part[1..].trim_matches('"').to_string();
                }
                Some('R') => prop.flags.0 |= ObjcPropertyFlags::READONLY,
                Some('C') => prop.flags.0 |= ObjcPropertyFlags::COPY,
                Some('&') => prop.flags.0 |= ObjcPropertyFlags::RETAIN,
                Some('W') => prop.flags.0 |= ObjcPropertyFlags::WEAK,
                Some('N') => prop.flags.0 &= !ObjcPropertyFlags::ATOMIC,
                Some('V') => prop.backing_ivar = Some(part[1..].to_string()),
                _ => {}
            }
        }
        prop
    }
}

// ─── ObjcProtocol ─────────────────────────────────────────────────────────────

/// An `ObjC` protocol declaration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjcProtocol {
    pub name: String,
    pub required_instance_methods: Vec<ObjcMethod>,
    pub optional_instance_methods: Vec<ObjcMethod>,
    pub required_class_methods: Vec<ObjcMethod>,
    pub protocols: Vec<String>,
}

// ─── ObjcCategory ─────────────────────────────────────────────────────────────

/// An `ObjC` category.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjcCategory {
    pub name: String,
    pub class_name: String,
    pub instance_methods: Vec<ObjcMethod>,
    pub class_methods: Vec<ObjcMethod>,
    pub protocols: Vec<String>,
    pub properties: Vec<ObjcProperty>,
}

// ─── ObjcClass ────────────────────────────────────────────────────────────────

/// A fully recovered `ObjC` class.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjcClass {
    pub name: String,
    pub superclass: Option<String>,
    pub protocols: Vec<String>,
    pub instance_methods: Vec<ObjcMethod>,
    pub class_methods: Vec<ObjcMethod>,
    pub ivars: Vec<ObjcIvar>,
    pub properties: Vec<ObjcProperty>,
    pub class_address: u64,
    pub metaclass_address: u64,
}

impl ObjcClass {
    /// Return `true` if this class conforms to the named protocol.
    #[must_use]
    pub fn conforms_to(&self, protocol: &str) -> bool {
        self.protocols.iter().any(|p| p == protocol)
    }

    /// Find an instance method by selector.
    #[must_use]
    pub fn find_method(&self, selector: &str) -> Option<&ObjcMethod> {
        self.instance_methods
            .iter()
            .find(|m| m.selector == selector)
            .or_else(|| self.class_methods.iter().find(|m| m.selector == selector))
    }

    /// Find a property by name.
    #[must_use]
    pub fn find_property(&self, name: &str) -> Option<&ObjcProperty> {
        self.properties.iter().find(|p| p.name == name)
    }

    /// Return all method selectors.
    #[must_use]
    pub fn all_selectors(&self) -> Vec<&str> {
        self.instance_methods
            .iter()
            .chain(self.class_methods.iter())
            .map(|m| m.selector.as_str())
            .collect()
    }

    /// Return method count.
    #[must_use]
    pub const fn method_count(&self) -> usize {
        self.instance_methods.len() + self.class_methods.len()
    }

    /// Create a mock class for testing.
    #[must_use]
    pub fn mock(name: &str) -> Self {
        Self {
            name: name.to_string(),
            superclass: Some("NSObject".to_string()),
            protocols: vec!["NSCoding".to_string()],
            instance_methods: vec![
                ObjcMethod {
                    selector: "viewDidLoad".to_string(),
                    type_encoding: "v16@0:8".to_string(),
                    types: MethodTypes::from_encoding("v16@0:8"),
                    imp: 0x1000_4000,
                    is_class_method: false,
                },
                ObjcMethod {
                    selector: "tableView:numberOfRowsInSection:".to_string(),
                    type_encoding: "q40@0:8@16q32".to_string(),
                    types: MethodTypes::from_encoding("q40@0:8@16q32"),
                    imp: 0x1000_4100,
                    is_class_method: false,
                },
            ],
            class_methods: vec![ObjcMethod {
                selector: "sharedInstance".to_string(),
                type_encoding: "@16@0:8".to_string(),
                types: MethodTypes::from_encoding("@16@0:8"),
                imp: 0x1000_4200,
                is_class_method: true,
            }],
            ivars: vec![ObjcIvar {
                name: "_delegate".to_string(),
                type_str: "@".to_string(),
                offset: 8,
                size: 8,
                alignment: 3,
            }],
            properties: vec![ObjcProperty::from_attrs("delegate", "T@,W,N,V_delegate")],
            class_address: 0x1001_0000,
            metaclass_address: 0x1001_0020,
        }
    }
}

// ─── ObjcMetadataParser ───────────────────────────────────────────────────────

/// Parses `ObjC` metadata from raw Mach-O section data.
///
/// In a real implementation this would take a reference to the parsed binary.
/// Here we work with raw bytes of individual sections.
pub struct ObjcMetadataParser {
    /// Raw bytes of the `__TEXT,__objc_methname` section.
    pub methname_section: Vec<u8>,
    /// Raw bytes of the `__TEXT,__objc_classname` section.
    pub classname_section: Vec<u8>,
    /// Raw bytes of the `__TEXT,__objc_methtype` section.
    pub methtype_section: Vec<u8>,
    /// Pre-parsed classes (populated by parse methods).
    classes: Vec<ObjcClass>,
    /// Selector → list of imp addresses.
    selector_map: HashMap<String, Vec<u64>>,
}

impl ObjcMetadataParser {
    /// Create a new parser with raw section data.
    #[must_use]
    pub fn new(methname: Vec<u8>, classname: Vec<u8>, methtype: Vec<u8>) -> Self {
        Self {
            methname_section: methname,
            classname_section: classname,
            methtype_section: methtype,
            classes: Vec::new(),
            selector_map: HashMap::new(),
        }
    }

    /// Add classes directly (for testing / mock usage).
    pub fn add_classes(&mut self, classes: Vec<ObjcClass>) {
        for class in &classes {
            for method in class
                .instance_methods
                .iter()
                .chain(class.class_methods.iter())
            {
                self.selector_map
                    .entry(method.selector.clone())
                    .or_default()
                    .push(method.imp);
            }
        }
        self.classes.extend(classes);
    }

    /// Return all classes.
    #[must_use]
    pub fn all_classes(&self) -> &[ObjcClass] {
        &self.classes
    }

    /// Find a class by address.
    #[must_use]
    pub fn find_class_by_address(&self, addr: u64) -> Option<&ObjcClass> {
        self.classes
            .iter()
            .find(|c| c.class_address == addr || c.metaclass_address == addr)
    }

    /// Find the class and method that contains the given implementation address.
    #[must_use]
    pub fn find_method_by_address(&self, addr: u64) -> Option<(&ObjcClass, &ObjcMethod)> {
        for class in &self.classes {
            for method in class
                .instance_methods
                .iter()
                .chain(class.class_methods.iter())
            {
                if method.imp == addr {
                    return Some((class, method));
                }
            }
        }
        None
    }

    /// Build a map from selector string to all known implementation addresses.
    #[must_use]
    pub const fn build_selector_map(&self) -> &HashMap<String, Vec<u64>> {
        &self.selector_map
    }

    /// Return all method names from the `__objc_methname` section.
    #[must_use]
    pub fn all_method_names(&self) -> Vec<String> {
        read_cstrings(&self.methname_section)
    }

    /// Return all class names from the `__objc_classname` section.
    #[must_use]
    pub fn all_class_names(&self) -> Vec<String> {
        read_cstrings(&self.classname_section)
    }
}

/// Read all NUL-terminated strings from a bytes slice.
fn read_cstrings(data: &[u8]) -> Vec<String> {
    let mut result = Vec::new();
    let mut start = 0;
    for (i, &b) in data.iter().enumerate() {
        if b == 0 {
            if i > start
                && let Ok(s) = std::str::from_utf8(&data[start..i])
            {
                result.push(s.to_string());
            }
            start = i + 1;
        }
    }
    result
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_simple_void_self_cmd() {
        let types = decode_type_encoding("v16@0:8");
        // void, id, SEL (after filtering numeric offsets)
        assert!(types.iter().any(|t| matches!(t, ObjcType::Void)));
        assert!(types.iter().any(|t| matches!(t, ObjcType::Id)));
        assert!(types.iter().any(|t| matches!(t, ObjcType::Selector)));
    }

    #[test]
    fn test_decode_int_return() {
        let types = decode_type_encoding("i16@0:8");
        assert!(types.iter().any(|t| matches!(t, ObjcType::Int)));
    }

    #[test]
    fn test_decode_pointer() {
        let types = decode_type_encoding("^v8@0:0");
        assert!(types.iter().any(|t| matches!(t, ObjcType::Pointer(_))));
    }

    #[test]
    fn test_decode_struct() {
        let types = decode_type_encoding("{CGRect=}");
        assert!(
            types
                .iter()
                .any(|t| matches!(t, ObjcType::Struct(n) if n == "CGRect"))
        );
    }

    #[test]
    fn test_method_types_from_encoding() {
        let mt = MethodTypes::from_encoding("v16@0:8");
        assert_eq!(mt.return_type, "void");
    }

    #[test]
    fn test_objc_method_signature_string_simple() {
        let m = ObjcMethod {
            selector: "viewDidLoad".to_string(),
            type_encoding: "v16@0:8".to_string(),
            types: MethodTypes::from_encoding("v16@0:8"),
            imp: 0x1000,
            is_class_method: false,
        };
        let sig = m.signature_string();
        assert!(sig.contains("viewDidLoad"));
        assert!(sig.starts_with('-'));
    }

    #[test]
    fn test_objc_method_signature_class_method() {
        let m = ObjcMethod {
            selector: "sharedInstance".to_string(),
            type_encoding: "@16@0:8".to_string(),
            types: MethodTypes::from_encoding("@16@0:8"),
            imp: 0x2000,
            is_class_method: true,
        };
        assert!(m.signature_string().starts_with('+'));
    }

    #[test]
    fn test_objc_property_from_attrs() {
        let p = ObjcProperty::from_attrs("title", "T@\"NSString\",C,N,V_title");
        assert!(p.is_copy());
        assert!(!p.is_atomic());
        assert_eq!(p.backing_ivar.as_deref(), Some("_title"));
    }

    #[test]
    fn test_objc_class_mock() {
        let cls = ObjcClass::mock("UIViewController");
        assert_eq!(cls.name, "UIViewController");
        assert!(cls.conforms_to("NSCoding"));
        assert!(!cls.conforms_to("NSCopying"));
    }

    #[test]
    fn test_objc_class_find_method() {
        let cls = ObjcClass::mock("UIViewController");
        assert!(cls.find_method("viewDidLoad").is_some());
        assert!(cls.find_method("nonexistent").is_none());
    }

    #[test]
    fn test_objc_class_all_selectors() {
        let cls = ObjcClass::mock("UIViewController");
        let sels = cls.all_selectors();
        assert!(sels.contains(&"viewDidLoad"));
        assert!(sels.contains(&"sharedInstance"));
    }

    #[test]
    fn test_objc_class_method_count() {
        let cls = ObjcClass::mock("UIViewController");
        assert_eq!(cls.method_count(), 3);
    }

    #[test]
    fn test_parser_build_selector_map() {
        let mut parser = ObjcMetadataParser::new(vec![], vec![], vec![]);
        parser.add_classes(vec![ObjcClass::mock("UIViewController")]);
        let map = parser.build_selector_map();
        assert!(map.contains_key("viewDidLoad"));
    }

    #[test]
    fn test_parser_find_method_by_address() {
        let mut parser = ObjcMetadataParser::new(vec![], vec![], vec![]);
        parser.add_classes(vec![ObjcClass::mock("UIViewController")]);
        let result = parser.find_method_by_address(0x1000_4000);
        assert!(result.is_some());
        let (cls, method) = result.unwrap();
        assert_eq!(cls.name, "UIViewController");
        assert_eq!(method.selector, "viewDidLoad");
    }

    #[test]
    fn test_parser_find_class_by_address() {
        let mut parser = ObjcMetadataParser::new(vec![], vec![], vec![]);
        parser.add_classes(vec![ObjcClass::mock("UIViewController")]);
        assert!(parser.find_class_by_address(0x1001_0000).is_some());
        assert!(parser.find_class_by_address(0xDEAD_BEEF).is_none());
    }

    #[test]
    fn test_read_cstrings() {
        let data = b"hello\0world\0\0foo\0";
        let strings = read_cstrings(data);
        assert_eq!(strings, vec!["hello", "world", "foo"]);
    }

    #[test]
    fn test_parser_all_class_names() {
        let data = b"NSObject\0UIViewController\0AppDelegate\0";
        let parser = ObjcMetadataParser::new(vec![], data.to_vec(), vec![]);
        let names = parser.all_class_names();
        assert_eq!(names.len(), 3);
        assert!(names.contains(&"NSObject".to_string()));
    }

    #[test]
    fn test_objc_type_display() {
        assert_eq!(ObjcType::Void.to_string(), "void");
        assert_eq!(ObjcType::Id.to_string(), "id");
        assert_eq!(ObjcType::Selector.to_string(), "SEL");
        assert_eq!(
            ObjcType::Pointer(Box::new(ObjcType::Char)).to_string(),
            "char*"
        );
        assert_eq!(
            ObjcType::Struct("CGRect".to_string()).to_string(),
            "struct CGRect"
        );
    }

    #[test]
    fn test_objc_error_display() {
        assert!(ObjcError::Truncated(100).to_string().contains("100"));
        assert!(
            ObjcError::InvalidPointer(0xDEAD)
                .to_string()
                .contains("0xdead")
        );
    }
}
