//! Java type system and descriptor parser.
//!
//! Implements parsing of JVM field descriptors and method descriptors as
//! defined in JVMS §4.3, plus a [`TypeHierarchy`] registry for tracking
//! inheritance relationships.
//!
//! # Field descriptor grammar
//!
//! ```text
//! FieldDescriptor : FieldType
//! FieldType       : BaseType | ObjectType | ArrayType
//! BaseType        : B | C | D | F | I | J | S | Z
//! ObjectType      : L ClassName ;
//! ArrayType       : [ ComponentType
//! ComponentType   : FieldType
//! ```
//!
//! # Method descriptor grammar
//!
//! ```text
//! MethodDescriptor : ( ParameterDescriptor* ) ReturnDescriptor
//! ReturnDescriptor : FieldType | V
//! ```

use std::collections::{HashMap, HashSet};
use std::fmt;

// ─────────────────────────────────────────────────────────────────────────────
// JavaType
// ─────────────────────────────────────────────────────────────────────────────

/// A resolved Java type.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum JavaType {
    // Primitive base types
    /// `B` — byte (signed 8-bit integer)
    Byte,
    /// `C` — char (unsigned 16-bit UTF-16 code unit)
    Char,
    /// `D` — double (64-bit IEEE 754)
    Double,
    /// `F` — float (32-bit IEEE 754)
    Float,
    /// `I` — int (signed 32-bit integer)
    Int,
    /// `J` — long (signed 64-bit integer)
    Long,
    /// `S` — short (signed 16-bit integer)
    Short,
    /// `Z` — boolean
    Boolean,
    /// `V` — void (only valid as a return type)
    Void,
    /// `L<ClassName>;` — reference to a class or interface
    Object(String),
    /// `[<ComponentType>` — array
    Array(Box<Self>),
}

impl JavaType {
    /// The JVM descriptor character for this type.
    #[must_use] 
    pub const fn descriptor_char(&self) -> char {
        match self {
            Self::Byte    => 'B',
            Self::Char    => 'C',
            Self::Double  => 'D',
            Self::Float   => 'F',
            Self::Int     => 'I',
            Self::Long    => 'J',
            Self::Short   => 'S',
            Self::Boolean => 'Z',
            Self::Void    => 'V',
            Self::Object(_) => 'L',
            Self::Array(_)  => '[',
        }
    }

    /// True if this is a primitive (non-reference) type.
    #[must_use] 
    pub const fn is_primitive(&self) -> bool {
        !matches!(self, Self::Object(_) | Self::Array(_))
    }

    /// True if this is a category-2 JVM type (long or double).
    #[must_use] 
    pub const fn is_category2(&self) -> bool {
        matches!(self, Self::Long | Self::Double)
    }

    /// The unqualified simple name (last component after `/`).
    #[must_use] 
    pub fn simple_name(&self) -> String {
        match self {
            Self::Object(fqn) => fqn.rsplit('/').next().unwrap_or(fqn).to_owned(),
            other => format!("{other}"),
        }
    }

    /// Number of JVM local-variable slots consumed.
    #[must_use] 
    pub const fn slot_count(&self) -> usize {
        if self.is_category2() { 2 } else { 1 }
    }

    /// Render back to a descriptor string.
    #[must_use] 
    pub fn to_descriptor(&self) -> String {
        match self {
            Self::Object(name) => format!("L{name};"),
            Self::Array(elem)  => format!("[{}", elem.to_descriptor()),
            other => other.descriptor_char().to_string(),
        }
    }
}

impl fmt::Display for JavaType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Byte    => write!(f, "byte"),
            Self::Char    => write!(f, "char"),
            Self::Double  => write!(f, "double"),
            Self::Float   => write!(f, "float"),
            Self::Int     => write!(f, "int"),
            Self::Long    => write!(f, "long"),
            Self::Short   => write!(f, "short"),
            Self::Boolean => write!(f, "boolean"),
            Self::Void    => write!(f, "void"),
            Self::Object(name) => write!(f, "{}", name.replace('/', ".")),
            Self::Array(elem)  => write!(f, "{elem}[]"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// FieldDescriptor / MethodDescriptor
// ─────────────────────────────────────────────────────────────────────────────

/// A parsed field descriptor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldDescriptor {
    pub field_type: JavaType,
}

impl FieldDescriptor {
    #[must_use] 
    pub const fn new(t: JavaType) -> Self { Self { field_type: t } }
    #[must_use] 
    pub fn to_descriptor(&self) -> String { self.field_type.to_descriptor() }
}

impl fmt::Display for FieldDescriptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.field_type)
    }
}

/// A parsed method descriptor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MethodDescriptor {
    pub params: Vec<JavaType>,
    pub return_type: JavaType,
}

impl MethodDescriptor {
    /// Total number of JVM parameter slots (including category-2 doubles).
    #[must_use] 
    pub fn param_slots(&self) -> usize {
        self.params.iter().map(JavaType::slot_count).sum()
    }

    /// Render back to a descriptor string.
    #[must_use] 
    pub fn to_descriptor(&self) -> String {
        let mut s = String::from("(");
        for p in &self.params { s.push_str(&p.to_descriptor()); }
        s.push(')');
        s.push_str(&self.return_type.to_descriptor());
        s
    }
}

impl fmt::Display for MethodDescriptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}(", self.return_type)?;
        for (i, p) in self.params.iter().enumerate() {
            if i > 0 { write!(f, ", ")?; }
            write!(f, "{p}")?;
        }
        write!(f, ")")
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DescriptorParser
// ─────────────────────────────────────────────────────────────────────────────

/// Parse errors for descriptor strings.
#[derive(Debug, Clone)]
pub struct DescriptorError {
    pub descriptor: String,
    pub position: usize,
    pub message: String,
}

impl fmt::Display for DescriptorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "descriptor parse error at col {} in {:?}: {}", self.position, self.descriptor, self.message)
    }
}

/// Parser for JVM field and method descriptors.
pub struct DescriptorParser;

impl DescriptorParser {
    /// Parse a field descriptor string into a [`FieldDescriptor`].
    pub fn parse_field(desc: &str) -> Result<FieldDescriptor, DescriptorError> {
        let chars: Vec<char> = desc.chars().collect();
        let (t, consumed) = Self::parse_type(&chars, 0, desc)?;
        if consumed != chars.len() {
            return Err(DescriptorError {
                descriptor: desc.to_owned(),
                position: consumed,
                message: "trailing characters after field descriptor".into(),
            });
        }
        Ok(FieldDescriptor::new(t))
    }

    /// Parse a method descriptor string into a [`MethodDescriptor`].
    pub fn parse_method(desc: &str) -> Result<MethodDescriptor, DescriptorError> {
        let chars: Vec<char> = desc.chars().collect();
        let mut pos = 0;

        // Expect '('
        if chars.get(pos) != Some(&'(') {
            return Err(DescriptorError {
                descriptor: desc.to_owned(),
                position: pos,
                message: "expected '('".into(),
            });
        }
        pos += 1;

        let mut params = Vec::new();
        while pos < chars.len() && chars[pos] != ')' {
            let (t, consumed) = Self::parse_type(&chars, pos, desc)?;
            pos = consumed;
            params.push(t);
        }

        // Expect ')'
        if chars.get(pos) != Some(&')') {
            return Err(DescriptorError {
                descriptor: desc.to_owned(),
                position: pos,
                message: "expected ')'".into(),
            });
        }
        pos += 1;

        let (return_type, _) = Self::parse_return_type(&chars, pos, desc)?;
        Ok(MethodDescriptor { params, return_type })
    }

    // ── Internal helpers ──────────────────────────────────────────────────────

    fn parse_type(chars: &[char], pos: usize, src: &str) -> Result<(JavaType, usize), DescriptorError> {
        if pos >= chars.len() {
            return Err(DescriptorError { descriptor: src.to_owned(), position: pos, message: "unexpected end".into() });
        }
        match chars[pos] {
            'B' => Ok((JavaType::Byte,    pos + 1)),
            'C' => Ok((JavaType::Char,    pos + 1)),
            'D' => Ok((JavaType::Double,  pos + 1)),
            'F' => Ok((JavaType::Float,   pos + 1)),
            'I' => Ok((JavaType::Int,     pos + 1)),
            'J' => Ok((JavaType::Long,    pos + 1)),
            'S' => Ok((JavaType::Short,   pos + 1)),
            'Z' => Ok((JavaType::Boolean, pos + 1)),
            'L' => {
                let end = chars[pos+1..].iter().position(|&c| c == ';')
                    .ok_or_else(|| DescriptorError { descriptor: src.to_owned(), position: pos, message: "unterminated object type".into() })?;
                let name: String = chars[pos+1..pos+1+end].iter().collect();
                Ok((JavaType::Object(name), pos + 1 + end + 1))
            }
            '[' => {
                let (elem, next) = Self::parse_type(chars, pos + 1, src)?;
                Ok((JavaType::Array(Box::new(elem)), next))
            }
            other => Err(DescriptorError {
                descriptor: src.to_owned(),
                position: pos,
                message: format!("unknown type character '{other}'"),
            }),
        }
    }

    fn parse_return_type(chars: &[char], pos: usize, src: &str) -> Result<(JavaType, usize), DescriptorError> {
        if pos >= chars.len() {
            return Err(DescriptorError { descriptor: src.to_owned(), position: pos, message: "expected return type".into() });
        }
        if chars[pos] == 'V' { return Ok((JavaType::Void, pos + 1)); }
        Self::parse_type(chars, pos, src)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TypeHierarchy
// ─────────────────────────────────────────────────────────────────────────────

/// Records class inheritance and interface implementation relationships.
///
/// Class names use binary (slash-separated) form: `"java/lang/Object"`.
#[derive(Debug, Default)]
pub struct TypeHierarchy {
    /// `class_name → superclass_name` (None for java/lang/Object)
    pub superclass: HashMap<String, Option<String>>,
    /// `class_name → set of implemented interfaces`
    pub interfaces: HashMap<String, HashSet<String>>,
    /// All known class names.
    pub classes: HashSet<String>,
}

impl TypeHierarchy {
    #[must_use] 
    pub fn new() -> Self { Self::default() }

    /// Register a class with its superclass and interfaces.
    pub fn add_class(
        &mut self,
        name: impl Into<String>,
        superclass: Option<impl Into<String>>,
        ifaces: &[&str],
    ) {
        let name = name.into();
        self.classes.insert(name.clone());
        self.superclass.insert(name.clone(), superclass.map(std::convert::Into::into));
        self.interfaces.entry(name).or_default().extend(ifaces.iter().map(std::string::ToString::to_string));
    }

    /// True if `child` is a subclass of `ancestor` (direct or indirect).
    #[must_use] 
    pub fn is_subclass_of(&self, child: &str, ancestor: &str) -> bool {
        if child == ancestor { return true; }
        let mut current = child;
        loop {
            match self.superclass.get(current) {
                Some(Some(parent)) => {
                    if parent == ancestor { return true; }
                    current = parent;
                }
                _ => return false,
            }
        }
    }

    /// True if `class` implements `iface` directly or via inheritance.
    #[must_use] 
    pub fn implements(&self, class: &str, iface: &str) -> bool {
        // Direct implementation
        if let Some(set) = self.interfaces.get(class)
            && set.contains(iface) { return true; }
        // Via superclass chain
        let mut current = class;
        loop {
            match self.superclass.get(current) {
                Some(Some(parent)) => {
                    if let Some(set) = self.interfaces.get(parent.as_str())
                        && set.contains(iface) { return true; }
                    current = parent;
                }
                _ => return false,
            }
        }
    }

    /// Return the full ancestor chain of a class (not including the class itself).
    #[must_use] 
    pub fn ancestors(&self, class: &str) -> Vec<String> {
        let mut chain = Vec::new();
        let mut current = class.to_owned();
        loop {
            match self.superclass.get(&current) {
                Some(Some(parent)) => {
                    chain.push(parent.clone());
                    current = parent.clone();
                }
                _ => break,
            }
        }
        chain
    }

    /// Compute the most specific common ancestor of two classes.
    #[must_use] 
    pub fn common_ancestor(&self, a: &str, b: &str) -> Option<String> {
        let ancestors_a: Vec<String> = std::iter::once(a.to_owned())
            .chain(self.ancestors(a)).collect();
        for anc in &ancestors_a {
            if self.is_subclass_of(b, anc) { return Some(anc.clone()); }
        }
        None
    }

    /// All classes that directly extend `parent`.
    #[must_use] 
    pub fn direct_subclasses(&self, parent: &str) -> Vec<&str> {
        self.superclass
            .iter()
            .filter(|(_, sup)| sup.as_deref() == Some(parent))
            .map(|(cls, _)| cls.as_str())
            .collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_int_field() {
        let fd = DescriptorParser::parse_field("I").unwrap();
        assert_eq!(fd.field_type, JavaType::Int);
    }

    #[test]
    fn test_parse_object_field() {
        let fd = DescriptorParser::parse_field("Ljava/lang/String;").unwrap();
        assert_eq!(fd.field_type, JavaType::Object("java/lang/String".into()));
    }

    #[test]
    fn test_parse_array_field() {
        let fd = DescriptorParser::parse_field("[I").unwrap();
        assert_eq!(fd.field_type, JavaType::Array(Box::new(JavaType::Int)));
    }

    #[test]
    fn test_parse_2d_array() {
        let fd = DescriptorParser::parse_field("[[B").unwrap();
        assert!(matches!(fd.field_type, JavaType::Array(_)));
    }

    #[test]
    fn test_parse_method_descriptor() {
        let md = DescriptorParser::parse_method("(ILjava/lang/String;)Z").unwrap();
        assert_eq!(md.params.len(), 2);
        assert_eq!(md.params[0], JavaType::Int);
        assert_eq!(md.params[1], JavaType::Object("java/lang/String".into()));
        assert_eq!(md.return_type, JavaType::Boolean);
    }

    #[test]
    fn test_void_method() {
        let md = DescriptorParser::parse_method("()V").unwrap();
        assert_eq!(md.return_type, JavaType::Void);
        assert!(md.params.is_empty());
    }

    #[test]
    fn test_method_roundtrip() {
        let desc = "(IJ)Ljava/lang/Object;";
        let md = DescriptorParser::parse_method(desc).unwrap();
        assert_eq!(md.to_descriptor(), desc);
    }

    #[test]
    fn test_field_roundtrip() {
        let desc = "Ljava/util/List;";
        let fd = DescriptorParser::parse_field(desc).unwrap();
        assert_eq!(fd.to_descriptor(), desc);
    }

    #[test]
    fn test_param_slots() {
        let md = DescriptorParser::parse_method("(IJ)V").unwrap();
        assert_eq!(md.param_slots(), 3); // int=1, long=2
    }

    #[test]
    fn test_type_hierarchy_subclass() {
        let mut h = TypeHierarchy::new();
        h.add_class("java/lang/Object", None::<&str>, &[]);
        h.add_class("java/lang/Number", Some("java/lang/Object"), &[]);
        h.add_class("java/lang/Integer", Some("java/lang/Number"), &[]);

        assert!(h.is_subclass_of("java/lang/Integer", "java/lang/Number"));
        assert!(h.is_subclass_of("java/lang/Integer", "java/lang/Object"));
        assert!(!h.is_subclass_of("java/lang/Number", "java/lang/Integer"));
    }

    #[test]
    fn test_type_hierarchy_implements() {
        let mut h = TypeHierarchy::new();
        h.add_class("java/lang/Object", None::<&str>, &[]);
        h.add_class("java/util/AbstractList", Some("java/lang/Object"), &["java/util/List"]);
        h.add_class("java/util/ArrayList", Some("java/util/AbstractList"), &[]);

        assert!(h.implements("java/util/AbstractList", "java/util/List"));
        // ArrayList inherits the interface via AbstractList
        assert!(h.implements("java/util/ArrayList", "java/util/List"));
    }

    #[test]
    fn test_common_ancestor() {
        let mut h = TypeHierarchy::new();
        h.add_class("java/lang/Object", None::<&str>, &[]);
        h.add_class("java/lang/Number", Some("java/lang/Object"), &[]);
        h.add_class("java/lang/Integer", Some("java/lang/Number"), &[]);
        h.add_class("java/lang/Double", Some("java/lang/Number"), &[]);

        let ca = h.common_ancestor("java/lang/Integer", "java/lang/Double").unwrap();
        assert_eq!(ca, "java/lang/Number");
    }

    #[test]
    fn test_ancestors_chain() {
        let mut h = TypeHierarchy::new();
        h.add_class("java/lang/Object", None::<&str>, &[]);
        h.add_class("A", Some("java/lang/Object"), &[]);
        h.add_class("B", Some("A"), &[]);

        let chain = h.ancestors("B");
        assert_eq!(chain, vec!["A", "java/lang/Object"]);
    }

    #[test]
    fn test_direct_subclasses() {
        let mut h = TypeHierarchy::new();
        h.add_class("java/lang/Object", None::<&str>, &[]);
        h.add_class("A", Some("java/lang/Object"), &[]);
        h.add_class("B", Some("java/lang/Object"), &[]);

        let mut subs = h.direct_subclasses("java/lang/Object");
        subs.sort_unstable();
        assert_eq!(subs, vec!["A", "B"]);
    }

    #[test]
    fn test_slot_count() {
        assert_eq!(JavaType::Int.slot_count(), 1);
        assert_eq!(JavaType::Long.slot_count(), 2);
        assert_eq!(JavaType::Double.slot_count(), 2);
        assert_eq!(JavaType::Object("X".into()).slot_count(), 1);
    }

    #[test]
    fn test_bad_method_descriptor() {
        assert!(DescriptorParser::parse_method("()Q").is_err());
    }
}
