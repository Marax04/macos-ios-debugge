//! Smali type resolution — convert Dalvik/JVM type descriptors to structured
//! [`SmaliType`] values and provide a cached [`SmaliTypeResolver`].

use std::collections::HashMap;
use std::fmt;

// ─── SmaliType ────────────────────────────────────────────────────────────────

/// A resolved Smali / Dalvik type.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SmaliType {
    /// `V` — void (return types only).
    Void,
    /// `Z` — boolean.
    Boolean,
    /// `B` — byte.
    Byte,
    /// `C` — char.
    Char,
    /// `S` — short.
    Short,
    /// `I` — int.
    Int,
    /// `J` — long.
    Long,
    /// `F` — float.
    Float,
    /// `D` — double.
    Double,
    /// `Lfully/qualified/ClassName;` — object reference.
    Object(String),
    /// `[<component>` — single-dimensional array.
    Array(Box<Self>),
    /// Multi-dimensional array shorthand (dimensions > 1 collapsed).
    MultiArray { dimensions: u8, component: Box<Self> },
    /// Unknown or unparseable descriptor.
    Unknown(String),
}

impl SmaliType {
    /// Width in 32-bit Dalvik register slots (1 or 2).
    #[must_use]
    pub const fn register_width(&self) -> u8 {
        match self {
            Self::Long | Self::Double => 2,
            _ => 1,
        }
    }

    /// Returns `true` if the type is a primitive (not a reference/array).
    #[must_use]
    pub const fn is_primitive(&self) -> bool {
        matches!(
            self,
            Self::Void
                | Self::Boolean
                | Self::Byte
                | Self::Char
                | Self::Short
                | Self::Int
                | Self::Long
                | Self::Float
                | Self::Double
        )
    }

    /// Returns `true` if this is a reference type (object or array).
    #[must_use]
    pub const fn is_reference(&self) -> bool {
        matches!(self, Self::Object(_) | Self::Array(_) | Self::MultiArray { .. })
    }

    /// Returns `true` for numeric types that can participate in arithmetic.
    #[must_use]
    pub const fn is_numeric(&self) -> bool {
        matches!(
            self,
            Self::Byte
                | Self::Char
                | Self::Short
                | Self::Int
                | Self::Long
                | Self::Float
                | Self::Double
        )
    }

    /// Returns the inner class name for `Object` types, stripping `L` and `;`.
    #[must_use]
    pub const fn class_name(&self) -> Option<&str> {
        if let Self::Object(name) = self {
            Some(name.as_str())
        } else {
            None
        }
    }

    /// Returns the component type of an array, or `None` for non-arrays.
    #[must_use]
    pub fn array_component(&self) -> Option<&Self> {
        match self {
            Self::Array(inner) => Some(inner),
            _ => None,
        }
    }

    /// Canonical JVM descriptor string for this type.
    #[must_use]
    pub fn to_descriptor(&self) -> String {
        match self {
            Self::Void => "V".to_string(),
            Self::Boolean => "Z".to_string(),
            Self::Byte => "B".to_string(),
            Self::Char => "C".to_string(),
            Self::Short => "S".to_string(),
            Self::Int => "I".to_string(),
            Self::Long => "J".to_string(),
            Self::Float => "F".to_string(),
            Self::Double => "D".to_string(),
            Self::Object(name) => format!("L{name};"),
            Self::Array(inner) => format!("[{}", inner.to_descriptor()),
            Self::MultiArray { dimensions, component } => {
                format!("{}{}", "[".repeat(*dimensions as usize), component.to_descriptor())
            }
            Self::Unknown(raw) => raw.clone(),
        }
    }

    /// Human-readable Java-like type name.
    #[must_use]
    pub fn java_name(&self) -> String {
        match self {
            Self::Void => "void".to_string(),
            Self::Boolean => "boolean".to_string(),
            Self::Byte => "byte".to_string(),
            Self::Char => "char".to_string(),
            Self::Short => "short".to_string(),
            Self::Int => "int".to_string(),
            Self::Long => "long".to_string(),
            Self::Float => "float".to_string(),
            Self::Double => "double".to_string(),
            Self::Object(name) => name.replace('/', "."),
            Self::Array(inner) => format!("{}[]", inner.java_name()),
            Self::MultiArray { dimensions, component } => {
                format!("{}{}", component.java_name(), "[]".repeat(*dimensions as usize))
            }
            Self::Unknown(raw) => format!("<unknown:{raw}>"),
        }
    }

    /// Simple name (last component after `/`).
    #[must_use]
    pub fn simple_name(&self) -> String {
        match self {
            Self::Object(name) => name
                .rsplit('/')
                .next()
                .unwrap_or(name.as_str())
                .to_string(),
            other => other.java_name(),
        }
    }
}

impl fmt::Display for SmaliType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.java_name())
    }
}

// ─── MethodSignature ─────────────────────────────────────────────────────────

/// A parsed Smali method signature: parameter types + return type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MethodSignature {
    pub parameters: Vec<SmaliType>,
    pub return_type: SmaliType,
}

impl MethodSignature {
    /// Parse a JVM method descriptor such as `(ILjava/lang/String;)V`.
    ///
    /// Returns `None` if the descriptor is malformed.
    #[must_use]
    pub fn parse(descriptor: &str) -> Option<Self> {
        let bytes = descriptor.as_bytes();
        if bytes.first() != Some(&b'(') {
            return None;
        }
        let close = bytes.iter().rposition(|&b| b == b')')?;
        let params_str = &descriptor[1..close];
        let ret_str = &descriptor[close + 1..];

        let parameters = parse_type_list(params_str);
        let return_type = parse_type_str(ret_str)?;
        Some(Self { parameters, return_type })
    }

    /// Total parameter register slots (wide types occupy 2 slots).
    #[must_use]
    pub fn parameter_slots(&self) -> usize {
        self.parameters.iter().map(|t| t.register_width() as usize).sum()
    }

    /// Reconstruct the descriptor string.
    #[must_use]
    pub fn to_descriptor(&self) -> String {
        let params: String = self.parameters.iter().map(SmaliType::to_descriptor).collect();
        format!("({params}){}", self.return_type.to_descriptor())
    }
}

impl fmt::Display for MethodSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let params: Vec<String> = self.parameters.iter().map(SmaliType::java_name).collect();
        write!(f, "({}) -> {}", params.join(", "), self.return_type)
    }
}

// ─── Parser helpers ───────────────────────────────────────────────────────────

/// Parse a sequence of type descriptors from a JVM parameter string.
fn parse_type_list(s: &str) -> Vec<SmaliType> {
    let mut result = Vec::new();
    let mut chars = s.chars().peekable();
    while chars.peek().is_some() {
        let remaining: String = chars.clone().collect();
        if let Some(ty) = parse_type_str(&remaining) {
            let consumed = ty.to_descriptor().len();
            for _ in 0..consumed {
                chars.next();
            }
            result.push(ty);
        } else {
            chars.next();
        }
    }
    result
}

/// Parse a single type descriptor from the start of `s`.
#[must_use]
pub fn parse_type_str(s: &str) -> Option<SmaliType> {
    let mut chars = s.chars();
    let first = chars.next()?;
    match first {
        'V' => Some(SmaliType::Void),
        'Z' => Some(SmaliType::Boolean),
        'B' => Some(SmaliType::Byte),
        'C' => Some(SmaliType::Char),
        'S' => Some(SmaliType::Short),
        'I' => Some(SmaliType::Int),
        'J' => Some(SmaliType::Long),
        'F' => Some(SmaliType::Float),
        'D' => Some(SmaliType::Double),
        'L' => {
            let rest: String = chars.collect();
            let end = rest.find(';')?;
            let name = rest[..end].to_string();
            Some(SmaliType::Object(name))
        }
        '[' => {
            let rest: String = chars.collect();
            // Count additional leading `[`
            let extra_dims = rest.chars().take_while(|&c| c == '[').count();
            let total_dims = 1 + u8::try_from(extra_dims).unwrap_or(u8::MAX - 1);
            let component_str = &rest[extra_dims..];
            let component = parse_type_str(component_str)?;
            if total_dims == 1 {
                Some(SmaliType::Array(Box::new(component)))
            } else {
                Some(SmaliType::MultiArray {
                    dimensions: total_dims,
                    component: Box::new(component),
                })
            }
        }
        _ => Some(SmaliType::Unknown(s.to_string())),
    }
}

// ─── SmaliTypeResolver ───────────────────────────────────────────────────────

/// Cached resolver for Smali type descriptors.
///
/// Resolving type descriptors is done frequently during disassembly; this
/// struct memoises results to avoid repeated string parsing.
pub struct SmaliTypeResolver {
    cache: HashMap<String, SmaliType>,
    class_hierarchy: HashMap<String, String>,
}

impl SmaliTypeResolver {
    /// Create a new, empty resolver.
    #[must_use]
    pub fn new() -> Self {
        Self {
            cache: HashMap::new(),
            class_hierarchy: HashMap::new(),
        }
    }

    /// Register a superclass relationship: `class` extends `superclass`.
    pub fn register_superclass(&mut self, class: impl Into<String>, superclass: impl Into<String>) {
        self.class_hierarchy.insert(class.into(), superclass.into());
    }

    /// Resolve a JVM type descriptor to a [`SmaliType`], using the cache.
    pub fn resolve_descriptor(&mut self, descriptor: &str) -> SmaliType {
        if let Some(cached) = self.cache.get(descriptor) {
            return cached.clone();
        }
        let ty = parse_type_str(descriptor)
            .unwrap_or_else(|| SmaliType::Unknown(descriptor.to_string()));
        self.cache.insert(descriptor.to_string(), ty.clone());
        ty
    }

    /// Resolve a method signature descriptor.
    #[must_use]
    pub fn resolve_method_signature(&mut self, descriptor: &str) -> Option<MethodSignature> {
        MethodSignature::parse(descriptor)
    }

    /// Look up the direct superclass of a class, if registered.
    #[must_use]
    pub fn superclass_of(&self, class: &str) -> Option<&str> {
        self.class_hierarchy.get(class).map(String::as_str)
    }

    /// Walk the superclass chain and return all ancestors in order.
    #[must_use]
    pub fn ancestor_chain(&self, class: &str) -> Vec<&str> {
        let mut chain = Vec::new();
        let mut current = class;
        let mut seen = std::collections::HashSet::new();
        while let Some(parent) = self.class_hierarchy.get(current) {
            if !seen.insert(parent.as_str()) {
                break;
            }
            chain.push(parent.as_str());
            current = parent.as_str();
        }
        chain
    }

    /// Returns `true` if `candidate` is the same class or an ancestor of `class`.
    #[must_use]
    pub fn is_assignable_from(&self, candidate: &str, class: &str) -> bool {
        if candidate == class {
            return true;
        }
        self.ancestor_chain(class).contains(&candidate)
    }

    /// Number of entries in the descriptor cache.
    #[must_use]
    pub fn cache_len(&self) -> usize {
        self.cache.len()
    }

    /// Clear the descriptor cache.
    pub fn clear_cache(&mut self) {
        self.cache.clear();
    }
}

impl Default for SmaliTypeResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for SmaliTypeResolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SmaliTypeResolver {{ cache: {}, hierarchy: {} }}",
            self.cache.len(),
            self.class_hierarchy.len()
        )
    }
}

// ─── FieldDescriptor ─────────────────────────────────────────────────────────

/// Parsed field reference of the form `Lowner/Class;->fieldName:Ldescriptor;`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldDescriptor {
    pub owner: SmaliType,
    pub name: String,
    pub field_type: SmaliType,
}

impl FieldDescriptor {
    /// Parse a Smali field reference string.
    ///
    /// Returns `None` if the string does not match the expected format.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        let arrow = s.find("->")?;
        let owner_str = &s[..arrow];
        let rest = &s[arrow + 2..];
        let colon = rest.find(':')?;
        let name = rest[..colon].to_string();
        let type_str = &rest[colon + 1..];
        let owner = parse_type_str(owner_str)?;
        let field_type = parse_type_str(type_str)?;
        Some(Self { owner, name, field_type })
    }

    /// Reconstruct the canonical field reference string.
    #[must_use]
    pub fn to_smali(&self) -> String {
        format!(
            "{}->{}:{}",
            self.owner.to_descriptor(),
            self.name,
            self.field_type.to_descriptor()
        )
    }
}

impl fmt::Display for FieldDescriptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_smali())
    }
}

// ─── MethodDescriptor ────────────────────────────────────────────────────────

/// Parsed method reference: `Lowner/Class;->methodName(params)RetType`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MethodDescriptor {
    pub owner: SmaliType,
    pub name: String,
    pub signature: MethodSignature,
}

impl MethodDescriptor {
    /// Parse a Smali method reference string.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        let arrow = s.find("->")?;
        let owner_str = &s[..arrow];
        let rest = &s[arrow + 2..];
        let paren = rest.find('(')?;
        let name = rest[..paren].to_string();
        let sig_str = &rest[paren..];
        let owner = parse_type_str(owner_str)?;
        let signature = MethodSignature::parse(sig_str)?;
        Some(Self { owner, name, signature })
    }

    /// Reconstruct the canonical method reference string.
    #[must_use]
    pub fn to_smali(&self) -> String {
        format!(
            "{}->{}{}",
            self.owner.to_descriptor(),
            self.name,
            self.signature.to_descriptor()
        )
    }
}

impl fmt::Display for MethodDescriptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_smali())
    }
}

// ─── TypeStats ───────────────────────────────────────────────────────────────

/// Aggregate statistics about a set of resolved types.
#[derive(Debug, Default, Clone)]
pub struct TypeStats {
    pub primitive_count: usize,
    pub object_count: usize,
    pub array_count: usize,
    pub void_count: usize,
    pub unknown_count: usize,
}

impl TypeStats {
    /// Build statistics from a slice of types.
    #[must_use]
    pub fn from_types(types: &[SmaliType]) -> Self {
        let mut s = Self::default();
        for ty in types {
            match ty {
                SmaliType::Void => s.void_count += 1,
                SmaliType::Object(_) => s.object_count += 1,
                SmaliType::Array(_) | SmaliType::MultiArray { .. } => s.array_count += 1,
                SmaliType::Unknown(_) => s.unknown_count += 1,
                _ => s.primitive_count += 1,
            }
        }
        s
    }

    /// Total count of all types.
    #[must_use]
    pub const fn total(&self) -> usize {
        self.primitive_count + self.object_count + self.array_count + self.void_count + self.unknown_count
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_primitives() {
        assert_eq!(parse_type_str("I"), Some(SmaliType::Int));
        assert_eq!(parse_type_str("J"), Some(SmaliType::Long));
        assert_eq!(parse_type_str("Z"), Some(SmaliType::Boolean));
        assert_eq!(parse_type_str("V"), Some(SmaliType::Void));
    }

    #[test]
    fn test_parse_object() {
        let ty = parse_type_str("Ljava/lang/String;").unwrap();
        assert_eq!(ty, SmaliType::Object("java/lang/String".to_string()));
        assert_eq!(ty.java_name(), "java.lang.String");
    }

    #[test]
    fn test_parse_array() {
        let ty = parse_type_str("[I").unwrap();
        assert_eq!(ty, SmaliType::Array(Box::new(SmaliType::Int)));
        assert_eq!(ty.java_name(), "int[]");
    }

    #[test]
    fn test_parse_multi_array() {
        let ty = parse_type_str("[[B").unwrap();
        if let SmaliType::MultiArray { dimensions, component } = ty {
            assert_eq!(dimensions, 2);
            assert_eq!(*component, SmaliType::Byte);
        } else {
            panic!("expected MultiArray");
        }
    }

    #[test]
    fn test_register_width() {
        assert_eq!(SmaliType::Int.register_width(), 1);
        assert_eq!(SmaliType::Long.register_width(), 2);
        assert_eq!(SmaliType::Double.register_width(), 2);
    }

    #[test]
    fn test_to_descriptor_roundtrip() {
        let descriptors = ["I", "Ljava/lang/Object;", "[Z", "V"];
        for d in descriptors {
            let ty = parse_type_str(d).unwrap();
            assert_eq!(ty.to_descriptor(), d);
        }
    }

    #[test]
    fn test_method_signature_parse() {
        let sig = MethodSignature::parse("(ILjava/lang/String;)V").unwrap();
        assert_eq!(sig.parameters.len(), 2);
        assert_eq!(sig.return_type, SmaliType::Void);
        assert_eq!(sig.parameter_slots(), 2);
    }

    #[test]
    fn test_method_signature_display() {
        let sig = MethodSignature::parse("(I)Z").unwrap();
        let s = sig.to_string();
        assert!(s.contains("int"));
        assert!(s.contains("boolean"));
    }

    #[test]
    fn test_resolver_cache() {
        let mut r = SmaliTypeResolver::new();
        r.resolve_descriptor("I");
        r.resolve_descriptor("Ljava/lang/String;");
        assert_eq!(r.cache_len(), 2);
        r.clear_cache();
        assert_eq!(r.cache_len(), 0);
    }

    #[test]
    fn test_resolver_hierarchy() {
        let mut r = SmaliTypeResolver::new();
        r.register_superclass("com/example/Foo", "com/example/Base");
        r.register_superclass("com/example/Base", "java/lang/Object");
        assert!(r.is_assignable_from("java/lang/Object", "com/example/Foo"));
        assert!(!r.is_assignable_from("com/example/Foo", "java/lang/Object"));
    }

    #[test]
    fn test_field_descriptor_parse() {
        let fd = FieldDescriptor::parse("Ljava/io/File;->path:Ljava/lang/String;").unwrap();
        assert_eq!(fd.name, "path");
        assert_eq!(fd.field_type, SmaliType::Object("java/lang/String".to_string()));
    }

    #[test]
    fn test_method_descriptor_parse() {
        let md = MethodDescriptor::parse("Ljava/lang/Object;->hashCode()I").unwrap();
        assert_eq!(md.name, "hashCode");
        assert_eq!(md.signature.return_type, SmaliType::Int);
    }

    #[test]
    fn test_type_stats() {
        let types = vec![
            SmaliType::Int,
            SmaliType::Object("Foo".to_string()),
            SmaliType::Array(Box::new(SmaliType::Byte)),
            SmaliType::Void,
            SmaliType::Unknown("?".to_string()),
        ];
        let stats = TypeStats::from_types(&types);
        assert_eq!(stats.primitive_count, 1);
        assert_eq!(stats.object_count, 1);
        assert_eq!(stats.array_count, 1);
        assert_eq!(stats.void_count, 1);
        assert_eq!(stats.unknown_count, 1);
        assert_eq!(stats.total(), 5);
    }
}
