//! `dalvik_type_system` — Dalvik/ART type system implementation.
//!
//! Parses DEX type descriptors, method signatures, builds type hierarchies,
//! handles arrays, interfaces, and primitive conversions.

use std::collections::{HashMap, HashSet};
use std::fmt;

use serde::{Deserialize, Serialize};

// ─── Error ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DalvikTypeError {
    InvalidDescriptor(String),
    UnknownClass(String),
    ParseError(String),
}

impl fmt::Display for DalvikTypeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidDescriptor(d) => write!(f, "invalid descriptor: '{d}'"),
            Self::UnknownClass(n) => write!(f, "unknown class: '{n}'"),
            Self::ParseError(msg) => write!(f, "parse error: {msg}"),
        }
    }
}

impl std::error::Error for DalvikTypeError {}

// ─── DalvikType ───────────────────────────────────────────────────────────────

/// A Dalvik/ART type.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DalvikType {
    /// void (V)
    Void,
    /// boolean (Z)
    Boolean,
    /// byte (B)
    Byte,
    /// char (C)
    Char,
    /// short (S)
    Short,
    /// int (I)
    Int,
    /// long (J)
    Long,
    /// float (F)
    Float,
    /// double (D)
    Double,
    /// Object reference (Ljava/lang/Object;)
    Object(String),
    /// Array type ([X or [[X etc.)
    Array(Box<Self>),
}

impl DalvikType {
    /// Returns `true` for primitive types (not void, not reference, not array).
    #[must_use] 
    pub const fn is_primitive(&self) -> bool {
        matches!(
            self,
            Self::Boolean
                | Self::Byte
                | Self::Char
                | Self::Short
                | Self::Int
                | Self::Long
                | Self::Float
                | Self::Double
        )
    }

    /// Returns `true` for wide types (long and double take two registers).
    #[must_use] 
    pub const fn is_wide(&self) -> bool {
        matches!(self, Self::Long | Self::Double)
    }

    /// Returns `true` for reference types (object or array).
    #[must_use] 
    pub const fn is_reference(&self) -> bool {
        matches!(self, Self::Object(_) | Self::Array(_))
    }

    /// Returns `true` if this is an array type.
    #[must_use] 
    pub const fn is_array(&self) -> bool {
        matches!(self, Self::Array(_))
    }

    /// Returns the element type if this is an array.
    #[must_use] 
    pub fn element_type(&self) -> Option<&Self> {
        if let Self::Array(inner) = self {
            Some(inner)
        } else {
            None
        }
    }

    /// Returns the nesting depth if this is an array (1 for `[I`, 2 for `[[I`, etc.).
    #[must_use] 
    pub fn array_depth(&self) -> usize {
        match self {
            Self::Array(inner) => 1 + inner.array_depth(),
            _ => 0,
        }
    }

    /// Register size in 32-bit words.
    #[must_use] 
    pub const fn register_size(&self) -> usize {
        if self.is_wide() { 2 } else { 1 }
    }

    /// The DEX type descriptor character.
    #[must_use] 
    pub fn descriptor(&self) -> String {
        match self {
            Self::Void => "V".into(),
            Self::Boolean => "Z".into(),
            Self::Byte => "B".into(),
            Self::Char => "C".into(),
            Self::Short => "S".into(),
            Self::Int => "I".into(),
            Self::Long => "J".into(),
            Self::Float => "F".into(),
            Self::Double => "D".into(),
            Self::Object(name) => format!("L{name};"),
            Self::Array(inner) => format!("[{}", inner.descriptor()),
        }
    }

    /// Human-readable Java-style name.
    #[must_use] 
    pub fn java_name(&self) -> String {
        match self {
            Self::Void => "void".into(),
            Self::Boolean => "boolean".into(),
            Self::Byte => "byte".into(),
            Self::Char => "char".into(),
            Self::Short => "short".into(),
            Self::Int => "int".into(),
            Self::Long => "long".into(),
            Self::Float => "float".into(),
            Self::Double => "double".into(),
            Self::Object(name) => name.replace('/', "."),
            Self::Array(inner) => format!("{}[]", inner.java_name()),
        }
    }
}

impl fmt::Display for DalvikType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.java_name())
    }
}

// ─── TypeDescriptorParser ────────────────────────────────────────────────────

/// Parses DEX type descriptor strings.
pub struct TypeDescriptorParser;

impl TypeDescriptorParser {
    /// Parse a single type descriptor, returning (`DalvikType`, `chars_consumed`).
    ///
    /// # Errors
    ///
    /// Returns [`DalvikTypeError`] if `desc` is not a well-formed Dalvik type
    /// descriptor.
    pub fn parse_one(desc: &str) -> Result<(DalvikType, usize), DalvikTypeError> {
        let chars: Vec<char> = desc.chars().collect();
        Self::parse_at(&chars, 0)
    }

    fn parse_at(chars: &[char], pos: usize) -> Result<(DalvikType, usize), DalvikTypeError> {
        if pos >= chars.len() {
            return Err(DalvikTypeError::ParseError(
                "unexpected end of descriptor".into(),
            ));
        }
        match chars[pos] {
            'V' => Ok((DalvikType::Void, 1)),
            'Z' => Ok((DalvikType::Boolean, 1)),
            'B' => Ok((DalvikType::Byte, 1)),
            'C' => Ok((DalvikType::Char, 1)),
            'S' => Ok((DalvikType::Short, 1)),
            'I' => Ok((DalvikType::Int, 1)),
            'J' => Ok((DalvikType::Long, 1)),
            'F' => Ok((DalvikType::Float, 1)),
            'D' => Ok((DalvikType::Double, 1)),
            'L' => {
                // Reference type: Ljava/lang/String;
                let start = pos + 1;
                let end = chars[start..]
                    .iter()
                    .position(|&c| c == ';')
                    .ok_or_else(|| DalvikTypeError::InvalidDescriptor(chars.iter().collect()))?;
                let name: String = chars[start..start + end].iter().collect();
                Ok((DalvikType::Object(name), end + 2)) // +2 for 'L' and ';'
            }
            '[' => {
                let (inner, inner_len) = Self::parse_at(chars, pos + 1)?;
                Ok((DalvikType::Array(Box::new(inner)), 1 + inner_len))
            }
            c => Err(DalvikTypeError::InvalidDescriptor(format!(
                "unknown type char: '{c}'"
            ))),
        }
    }

    /// Parse a full descriptor string (one type only).
    ///
    /// # Errors
    ///
    /// Returns [`DalvikTypeError`] if `desc` is not a well-formed Dalvik type
    /// descriptor, or if it is followed by trailing characters.
    pub fn parse(desc: &str) -> Result<DalvikType, DalvikTypeError> {
        let (ty, consumed) = Self::parse_one(desc)?;
        if consumed != desc.chars().count() {
            return Err(DalvikTypeError::InvalidDescriptor(format!(
                "trailing chars after type in '{desc}'"
            )));
        }
        Ok(ty)
    }
}

// ─── MethodSignature ─────────────────────────────────────────────────────────

/// A parsed DEX method signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MethodSignature {
    pub params: Vec<DalvikType>,
    pub return_type: DalvikType,
    pub raw: String,
}

impl MethodSignature {
    /// Parse a DEX method descriptor like "(ILjava/lang/String;)V".
    ///
    /// # Errors
    ///
    /// Returns [`DalvikTypeError`] if `descriptor` is not a well-formed method
    /// descriptor.
    pub fn parse(descriptor: &str) -> Result<Self, DalvikTypeError> {
        let chars: Vec<char> = descriptor.chars().collect();
        if chars.first() != Some(&'(') {
            return Err(DalvikTypeError::InvalidDescriptor(descriptor.into()));
        }
        let close_paren = chars
            .iter()
            .position(|&c| c == ')')
            .ok_or_else(|| DalvikTypeError::InvalidDescriptor(descriptor.into()))?;

        let mut params = Vec::new();
        let mut pos = 1; // skip '('
        while pos < close_paren {
            let (ty, consumed) = TypeDescriptorParser::parse_at(&chars, pos)?;
            params.push(ty);
            pos += consumed;
        }

        let return_str: String = chars[close_paren + 1..].iter().collect();
        let return_type = TypeDescriptorParser::parse(&return_str)?;

        Ok(Self {
            params,
            return_type,
            raw: descriptor.into(),
        })
    }

    /// Total number of register slots needed for parameters.
    #[must_use] 
    pub fn param_register_slots(&self) -> usize {
        self.params.iter().map(DalvikType::register_size).sum()
    }

    /// Java-style representation.
    #[must_use] 
    pub fn java_repr(&self, method_name: &str) -> String {
        let params: Vec<String> = self.params.iter().map(DalvikType::java_name).collect();
        format!(
            "{} {}({})",
            self.return_type.java_name(),
            method_name,
            params.join(", ")
        )
    }
}

impl fmt::Display for MethodSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.raw)
    }
}

// ─── ArrayType ───────────────────────────────────────────────────────────────

/// Helper for creating and inspecting array types.
pub struct ArrayType;

impl ArrayType {
    /// Create an array type of the given depth.
    #[must_use] 
    pub fn of(element: DalvikType, depth: usize) -> DalvikType {
        let mut ty = element;
        for _ in 0..depth {
            ty = DalvikType::Array(Box::new(ty));
        }
        ty
    }

    /// Get the base element type (strip all array wrappers).
    #[must_use] 
    pub fn base_type(ty: &DalvikType) -> &DalvikType {
        match ty {
            DalvikType::Array(inner) => Self::base_type(inner),
            other => other,
        }
    }
}

// ─── PrimitiveConversion ──────────────────────────────────────────────────────

/// DEX primitive type conversion rules.
pub struct PrimitiveConversion;

impl PrimitiveConversion {
    /// Widening conversions (e.g. int → long is widening).
    #[must_use] 
    pub const fn can_widen(from: &DalvikType, to: &DalvikType) -> bool {
        matches!(
            (from, to),
            (DalvikType::Byte,
DalvikType::Short | DalvikType::Int | DalvikType::Long | DalvikType::Float |
DalvikType::Double) | (DalvikType::Short | DalvikType::Char, DalvikType::Int)
| (DalvikType::Short | DalvikType::Char | DalvikType::Int, DalvikType::Long) |
(DalvikType::Short | DalvikType::Char | DalvikType::Int | DalvikType::Long,
DalvikType::Float) |
(DalvikType::Short | DalvikType::Char | DalvikType::Int | DalvikType::Long |
DalvikType::Float, DalvikType::Double)
        )
    }

    /// Narrowing conversions (may lose precision).
    #[must_use] 
    pub const fn can_narrow(from: &DalvikType, to: &DalvikType) -> bool {
        from.is_primitive() && to.is_primitive() && Self::can_widen(to, from)
    }

    /// The Dalvik-bytecode arithmetic promotion of two types.
    #[must_use] 
    pub fn common_type(a: &DalvikType, b: &DalvikType) -> DalvikType {
        if a == b {
            return a.clone();
        }
        if Self::can_widen(a, b) {
            b.clone()
        } else if Self::can_widen(b, a) {
            a.clone()
        } else {
            DalvikType::Int // default promotion
        }
    }
}

// ─── TypeHierarchy ───────────────────────────────────────────────────────────

/// The class hierarchy for object types in a DEX file.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct TypeHierarchy {
    /// Maps class name → parent class name.
    pub superclasses: HashMap<String, String>,
    /// Maps class name → set of implemented interfaces.
    pub interfaces: HashMap<String, HashSet<String>>,
}

impl TypeHierarchy {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a class with its superclass.
    pub fn register_class(&mut self, class: impl Into<String>, superclass: impl Into<String>) {
        self.superclasses.insert(class.into(), superclass.into());
    }

    /// Register an interface implementation.
    pub fn register_interface(&mut self, class: impl Into<String>, iface: impl Into<String>) {
        self.interfaces
            .entry(class.into())
            .or_default()
            .insert(iface.into());
    }

    /// Get the superclass chain up to java/lang/Object.
    #[must_use] 
    pub fn superclass_chain(&self, class: &str) -> Vec<String> {
        let mut chain = Vec::new();
        let mut current = class.to_string();
        let mut visited = HashSet::new();
        while let Some(parent) = self.superclasses.get(&current) {
            if !visited.insert(parent.clone()) {
                break; // cycle guard
            }
            chain.push(parent.clone());
            current = parent.clone();
        }
        chain
    }

    /// Returns `true` if `derived` is a subclass of `base`.
    #[must_use] 
    pub fn is_subclass_of(&self, derived: &str, base: &str) -> bool {
        if derived == base {
            return true;
        }
        self.superclass_chain(derived).contains(&base.to_string())
    }

    /// Returns `true` if `class` implements `interface`.
    #[must_use] 
    pub fn implements(&self, class: &str, interface: &str) -> bool {
        if let Some(ifaces) = self.interfaces.get(class)
            && ifaces.contains(interface) {
                return true;
            }
        // Check through superclass chain.
        for parent in self.superclass_chain(class) {
            if let Some(ifaces) = self.interfaces.get(&parent)
                && ifaces.contains(interface) {
                    return true;
                }
        }
        false
    }
}

// ─── InterfaceSet ────────────────────────────────────────────────────────────

/// Tracks all interfaces defined in a DEX file.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct InterfaceSet {
    pub interfaces: HashSet<String>,
}

impl InterfaceSet {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&mut self, name: impl Into<String>) {
        self.interfaces.insert(name.into());
    }

    #[must_use] 
    pub fn is_interface(&self, name: &str) -> bool {
        self.interfaces.contains(name)
    }

    #[must_use] 
    pub fn len(&self) -> usize {
        self.interfaces.len()
    }

    /// Returns `true` when [`len`](Self::len) is zero.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn primitive_types_descriptors() {
        assert_eq!(DalvikType::Void.descriptor(), "V");
        assert_eq!(DalvikType::Boolean.descriptor(), "Z");
        assert_eq!(DalvikType::Byte.descriptor(), "B");
        assert_eq!(DalvikType::Char.descriptor(), "C");
        assert_eq!(DalvikType::Short.descriptor(), "S");
        assert_eq!(DalvikType::Int.descriptor(), "I");
        assert_eq!(DalvikType::Long.descriptor(), "J");
        assert_eq!(DalvikType::Float.descriptor(), "F");
        assert_eq!(DalvikType::Double.descriptor(), "D");
    }

    #[test]
    fn object_type_descriptor() {
        let ty = DalvikType::Object("java/lang/String".into());
        assert_eq!(ty.descriptor(), "Ljava/lang/String;");
    }

    #[test]
    fn array_type_descriptor() {
        let ty = DalvikType::Array(Box::new(DalvikType::Int));
        assert_eq!(ty.descriptor(), "[I");
    }

    #[test]
    fn nested_array_descriptor() {
        let ty = DalvikType::Array(Box::new(DalvikType::Array(Box::new(DalvikType::Int))));
        assert_eq!(ty.descriptor(), "[[I");
    }

    #[test]
    fn java_names() {
        assert_eq!(DalvikType::Int.java_name(), "int");
        assert_eq!(
            DalvikType::Object("java/lang/Object".into()).java_name(),
            "java.lang.Object"
        );
        assert_eq!(
            DalvikType::Array(Box::new(DalvikType::Int)).java_name(),
            "int[]"
        );
    }

    #[test]
    fn is_wide() {
        assert!(DalvikType::Long.is_wide());
        assert!(DalvikType::Double.is_wide());
        assert!(!DalvikType::Int.is_wide());
    }

    #[test]
    fn is_reference() {
        assert!(DalvikType::Object("foo".into()).is_reference());
        assert!(DalvikType::Array(Box::new(DalvikType::Int)).is_reference());
        assert!(!DalvikType::Int.is_reference());
    }

    #[test]
    fn register_size() {
        assert_eq!(DalvikType::Long.register_size(), 2);
        assert_eq!(DalvikType::Int.register_size(), 1);
    }

    #[test]
    fn array_depth() {
        let arr = DalvikType::Array(Box::new(DalvikType::Array(Box::new(DalvikType::Int))));
        assert_eq!(arr.array_depth(), 2);
        assert_eq!(DalvikType::Int.array_depth(), 0);
    }

    #[test]
    fn parse_primitive() {
        assert_eq!(TypeDescriptorParser::parse("I").unwrap(), DalvikType::Int);
        assert_eq!(
            TypeDescriptorParser::parse("Z").unwrap(),
            DalvikType::Boolean
        );
        assert_eq!(TypeDescriptorParser::parse("V").unwrap(), DalvikType::Void);
    }

    #[test]
    fn parse_object() {
        let ty = TypeDescriptorParser::parse("Ljava/lang/String;").unwrap();
        assert_eq!(ty, DalvikType::Object("java/lang/String".into()));
    }

    #[test]
    fn parse_array() {
        let ty = TypeDescriptorParser::parse("[I").unwrap();
        assert_eq!(ty, DalvikType::Array(Box::new(DalvikType::Int)));
    }

    #[test]
    fn parse_array_of_object() {
        let ty = TypeDescriptorParser::parse("[Ljava/lang/String;").unwrap();
        assert_eq!(
            ty,
            DalvikType::Array(Box::new(DalvikType::Object("java/lang/String".into())))
        );
    }

    #[test]
    fn parse_invalid() {
        let result = TypeDescriptorParser::parse("X");
        assert!(result.is_err());
    }

    #[test]
    fn parse_method_signature_simple() {
        let sig = MethodSignature::parse("(I)V").unwrap();
        assert_eq!(sig.params.len(), 1);
        assert_eq!(sig.params[0], DalvikType::Int);
        assert_eq!(sig.return_type, DalvikType::Void);
    }

    #[test]
    fn parse_method_signature_multiple_params() {
        let sig = MethodSignature::parse("(IJZ)Ljava/lang/String;").unwrap();
        assert_eq!(sig.params.len(), 3);
        assert_eq!(sig.params[0], DalvikType::Int);
        assert_eq!(sig.params[1], DalvikType::Long);
        assert_eq!(sig.params[2], DalvikType::Boolean);
        assert_eq!(
            sig.return_type,
            DalvikType::Object("java/lang/String".into())
        );
    }

    #[test]
    fn parse_method_signature_no_params() {
        let sig = MethodSignature::parse("()V").unwrap();
        assert!(sig.params.is_empty());
        assert_eq!(sig.return_type, DalvikType::Void);
    }

    #[test]
    fn method_signature_register_slots() {
        let sig = MethodSignature::parse("(IJI)V").unwrap();
        // int=1, long=2, int=1 → total 4
        assert_eq!(sig.param_register_slots(), 4);
    }

    #[test]
    fn method_signature_java_repr() {
        let sig = MethodSignature::parse("(I)V").unwrap();
        let repr = sig.java_repr("myMethod");
        assert!(repr.contains("void"));
        assert!(repr.contains("myMethod"));
        assert!(repr.contains("int"));
    }

    #[test]
    fn array_type_of() {
        let arr = ArrayType::of(DalvikType::Int, 2);
        assert_eq!(arr.array_depth(), 2);
    }

    #[test]
    fn array_type_base() {
        let arr = DalvikType::Array(Box::new(DalvikType::Array(Box::new(DalvikType::Int))));
        assert_eq!(ArrayType::base_type(&arr), &DalvikType::Int);
    }

    #[test]
    fn primitive_conversion_widening() {
        assert!(PrimitiveConversion::can_widen(
            &DalvikType::Int,
            &DalvikType::Long
        ));
        assert!(PrimitiveConversion::can_widen(
            &DalvikType::Float,
            &DalvikType::Double
        ));
        assert!(!PrimitiveConversion::can_widen(
            &DalvikType::Long,
            &DalvikType::Int
        ));
    }

    #[test]
    fn primitive_conversion_narrowing() {
        assert!(PrimitiveConversion::can_narrow(
            &DalvikType::Long,
            &DalvikType::Int
        ));
        assert!(!PrimitiveConversion::can_narrow(
            &DalvikType::Int,
            &DalvikType::Long
        ));
    }

    #[test]
    fn type_hierarchy_superclass_chain() {
        let mut h = TypeHierarchy::new();
        h.register_class("C", "B");
        h.register_class("B", "A");
        h.register_class("A", "java/lang/Object");
        let chain = h.superclass_chain("C");
        assert!(chain.contains(&"B".to_string()));
        assert!(chain.contains(&"A".to_string()));
    }

    #[test]
    fn type_hierarchy_is_subclass() {
        let mut h = TypeHierarchy::new();
        h.register_class("Dog", "Animal");
        h.register_class("Animal", "java/lang/Object");
        assert!(h.is_subclass_of("Dog", "Animal"));
        assert!(h.is_subclass_of("Dog", "Dog"));
        assert!(!h.is_subclass_of("Animal", "Dog"));
    }

    #[test]
    fn type_hierarchy_implements() {
        let mut h = TypeHierarchy::new();
        h.register_interface("ArrayList", "java/util/List");
        assert!(h.implements("ArrayList", "java/util/List"));
        assert!(!h.implements("ArrayList", "java/util/Set"));
    }

    #[test]
    fn interface_set_add_check() {
        let mut ifaces = InterfaceSet::new();
        ifaces.add("java/util/Runnable");
        assert!(ifaces.is_interface("java/util/Runnable"));
        assert!(!ifaces.is_interface("java/lang/String"));
        assert_eq!(ifaces.len(), 1);
    }

    #[test]
    fn dalvik_type_error_display() {
        let e = DalvikTypeError::InvalidDescriptor("X".into());
        assert!(e.to_string().contains('X'));
    }
}
