//! DEX type system: type descriptors, class types, primitive types, method prototypes.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// PrimitiveKind
// ---------------------------------------------------------------------------

/// The kind of a DEX primitive type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PrimitiveKind {
    Void,
    Boolean,
    Byte,
    Short,
    Char,
    Int,
    Long,
    Float,
    Double,
}

impl PrimitiveKind {
    /// Return the single-character DEX type descriptor for this primitive.
    #[must_use]
    pub const fn descriptor_char(self) -> char {
        match self {
            Self::Void => 'V',
            Self::Boolean => 'Z',
            Self::Byte => 'B',
            Self::Short => 'S',
            Self::Char => 'C',
            Self::Int => 'I',
            Self::Long => 'J',
            Self::Float => 'F',
            Self::Double => 'D',
        }
    }

    /// Size in bytes (0 for Void).
    #[must_use]
    pub const fn byte_size(self) -> u32 {
        match self {
            Self::Void => 0,
            Self::Boolean | Self::Byte => 1,
            Self::Short | Self::Char => 2,
            Self::Int | Self::Float => 4,
            Self::Long | Self::Double => 8,
        }
    }

    /// Number of register slots (2 for Long/Double, 1 otherwise).
    #[must_use]
    pub const fn register_slots(self) -> u32 {
        match self {
            Self::Long | Self::Double => 2,
            _ => 1,
        }
    }

    /// Whether this primitive is a wide (64-bit) type.
    #[must_use]
    pub const fn is_wide(self) -> bool {
        matches!(self, Self::Long | Self::Double)
    }

    /// Parse from a DEX descriptor character.
    #[must_use]
    pub const fn from_char(c: char) -> Option<Self> {
        match c {
            'V' => Some(Self::Void),
            'Z' => Some(Self::Boolean),
            'B' => Some(Self::Byte),
            'S' => Some(Self::Short),
            'C' => Some(Self::Char),
            'I' => Some(Self::Int),
            'J' => Some(Self::Long),
            'F' => Some(Self::Float),
            'D' => Some(Self::Double),
            _ => None,
        }
    }

    /// Java name of the primitive type.
    #[must_use]
    pub const fn java_name(self) -> &'static str {
        match self {
            Self::Void => "void",
            Self::Boolean => "boolean",
            Self::Byte => "byte",
            Self::Short => "short",
            Self::Char => "char",
            Self::Int => "int",
            Self::Long => "long",
            Self::Float => "float",
            Self::Double => "double",
        }
    }
}

impl std::fmt::Display for PrimitiveKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.java_name())
    }
}

// ---------------------------------------------------------------------------
// ClassType
// ---------------------------------------------------------------------------

/// A DEX class type, parsed from a descriptor like `Ljava/lang/String;`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ClassType {
    /// The full descriptor including `L` and `;` (e.g., `Ljava/lang/String;`).
    pub descriptor: String,
    /// The internal class name with `/` separators (e.g., `java/lang/String`).
    pub internal_name: String,
}

impl ClassType {
    /// Parse a class type from a descriptor string.
    ///
    /// # Errors
    ///
    /// Returns `None` if the descriptor is not a valid class descriptor.
    #[must_use]
    pub fn from_descriptor(descriptor: &str) -> Option<Self> {
        if descriptor.starts_with('L') && descriptor.ends_with(';') {
            let internal = descriptor[1..descriptor.len() - 1].to_owned();
            Some(Self {
                descriptor: descriptor.to_owned(),
                internal_name: internal,
            })
        } else {
            None
        }
    }

    /// Return the simple class name (after the last `/`).
    #[must_use]
    pub fn simple_name(&self) -> &str {
        self.internal_name
            .rsplit('/')
            .next()
            .unwrap_or(&self.internal_name)
    }

    /// Return the package name (everything before the last `/`).
    #[must_use]
    pub fn package_name(&self) -> Option<&str> {
        let pos = self.internal_name.rfind('/')?;
        Some(&self.internal_name[..pos])
    }

    /// Convert the internal name to a Java-style dotted name.
    #[must_use]
    pub fn java_name(&self) -> String {
        self.internal_name.replace('/', ".")
    }

    /// Whether this class is in the `java.lang` package.
    #[must_use]
    pub fn is_java_lang(&self) -> bool {
        self.internal_name.starts_with("java/lang/")
    }

    /// Whether this class is in the `android.` hierarchy.
    #[must_use]
    pub fn is_android(&self) -> bool {
        self.internal_name.starts_with("android/")
    }

    /// Depth of the package hierarchy.
    #[must_use]
    pub fn package_depth(&self) -> usize {
        self.internal_name.chars().filter(|&c| c == '/').count()
    }
}

impl std::fmt::Display for ClassType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.descriptor)
    }
}

// ---------------------------------------------------------------------------
// TypeDescriptor
// ---------------------------------------------------------------------------

/// A fully parsed DEX type descriptor.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TypeDescriptor {
    Primitive(PrimitiveKind),
    Class(ClassType),
    Array { dimensions: u32, element: Box<Self> },
}

impl TypeDescriptor {
    /// Parse a type descriptor from a string.
    ///
    /// Returns `None` if the descriptor is invalid.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        Self::parse_at(s.as_bytes(), 0).map(|(td, _)| td)
    }

    fn parse_at(bytes: &[u8], offset: usize) -> Option<(Self, usize)> {
        if offset >= bytes.len() {
            return None;
        }
        match bytes[offset] as char {
            'V' => Some((Self::Primitive(PrimitiveKind::Void), offset + 1)),
            'Z' => Some((Self::Primitive(PrimitiveKind::Boolean), offset + 1)),
            'B' => Some((Self::Primitive(PrimitiveKind::Byte), offset + 1)),
            'S' => Some((Self::Primitive(PrimitiveKind::Short), offset + 1)),
            'C' => Some((Self::Primitive(PrimitiveKind::Char), offset + 1)),
            'I' => Some((Self::Primitive(PrimitiveKind::Int), offset + 1)),
            'J' => Some((Self::Primitive(PrimitiveKind::Long), offset + 1)),
            'F' => Some((Self::Primitive(PrimitiveKind::Float), offset + 1)),
            'D' => Some((Self::Primitive(PrimitiveKind::Double), offset + 1)),
            'L' => {
                let start = offset;
                let end = bytes[offset..].iter().position(|&b| b == b';')? + offset + 1;
                let desc = std::str::from_utf8(&bytes[start..end]).ok()?;
                let ct = ClassType::from_descriptor(desc)?;
                Some((Self::Class(ct), end))
            }
            '[' => {
                let mut dims = 0u32;
                let mut pos = offset;
                while pos < bytes.len() && bytes[pos] == b'[' {
                    dims += 1;
                    pos += 1;
                }
                let (element, next) = Self::parse_at(bytes, pos)?;
                Some((
                    Self::Array {
                        dimensions: dims,
                        element: Box::new(element),
                    },
                    next,
                ))
            }
            _ => None,
        }
    }

    /// Number of register slots this type occupies.
    #[must_use]
    pub const fn register_slots(&self) -> u32 {
        match self {
            Self::Primitive(p) => p.register_slots(),
            Self::Class(_) | Self::Array { .. } => 1,
        }
    }

    /// Whether this type is void.
    #[must_use]
    pub const fn is_void(&self) -> bool {
        matches!(self, Self::Primitive(PrimitiveKind::Void))
    }

    /// Whether this type is a reference type (class or array).
    #[must_use]
    pub const fn is_reference(&self) -> bool {
        matches!(self, Self::Class(_) | Self::Array { .. })
    }

    /// Whether this type is a wide (64-bit) type.
    #[must_use]
    pub const fn is_wide(&self) -> bool {
        match self {
            Self::Primitive(p) => p.is_wide(),
            _ => false,
        }
    }

    /// Return the DEX descriptor string.
    #[must_use]
    pub fn descriptor(&self) -> String {
        match self {
            Self::Primitive(p) => p.descriptor_char().to_string(),
            Self::Class(ct) => ct.descriptor.clone(),
            Self::Array { dimensions, element } => {
                let brackets: String = std::iter::repeat_n('[', *dimensions as usize).collect();
                format!("{brackets}{}", element.descriptor())
            }
        }
    }

    /// Return a human-readable Java-style name.
    #[must_use]
    pub fn java_name(&self) -> String {
        match self {
            Self::Primitive(p) => p.java_name().to_owned(),
            Self::Class(ct) => ct.java_name(),
            Self::Array { dimensions, element } => {
                let brackets: String = "[]".repeat(*dimensions as usize);
                format!("{}{brackets}", element.java_name())
            }
        }
    }
}

impl std::fmt::Display for TypeDescriptor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.descriptor())
    }
}

// ---------------------------------------------------------------------------
// MethodProto — method prototype (shorty + params + return type)
// ---------------------------------------------------------------------------

/// A DEX method prototype, corresponding to a `proto_id_item`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MethodProto {
    /// Short-form descriptor (e.g., `"VIL"`).
    pub shorty: String,
    /// Return type.
    pub return_type: TypeDescriptor,
    /// Parameter types.
    pub parameters: Vec<TypeDescriptor>,
}

impl MethodProto {
    /// Create a new method prototype.
    #[must_use]
    pub fn new(
        shorty: impl Into<String>,
        return_type: TypeDescriptor,
        parameters: Vec<TypeDescriptor>,
    ) -> Self {
        Self {
            shorty: shorty.into(),
            return_type,
            parameters,
        }
    }

    /// Total number of register slots consumed by parameters.
    #[must_use]
    pub fn parameter_register_count(&self) -> u32 {
        self.parameters.iter().map(TypeDescriptor::register_slots).sum()
    }

    /// Total register slots including return value (0 for void).
    #[must_use]
    pub fn total_slots(&self) -> u32 {
        self.parameter_register_count() + self.return_type.register_slots()
    }

    /// Return a Java-style signature string like `(int, String)void`.
    #[must_use]
    pub fn java_signature(&self) -> String {
        let params: Vec<String> = self.parameters.iter().map(TypeDescriptor::java_name).collect();
        format!("({}){}", params.join(", "), self.return_type.java_name())
    }

    /// Return the full DEX descriptor string like `(ILjava/lang/String;)V`.
    #[must_use]
    pub fn dex_descriptor(&self) -> String {
        let params: String = self.parameters.iter().map(TypeDescriptor::descriptor).collect();
        format!("({}){}", params, self.return_type.descriptor())
    }

    /// Whether this method returns void.
    #[must_use]
    pub const fn returns_void(&self) -> bool {
        self.return_type.is_void()
    }

    /// Whether this method takes no parameters.
    #[must_use]
    pub const fn is_no_args(&self) -> bool {
        self.parameters.is_empty()
    }
}

impl std::fmt::Display for MethodProto {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.dex_descriptor())
    }
}

// ---------------------------------------------------------------------------
// DexTypeSystem
// ---------------------------------------------------------------------------

/// Registry of all types and method prototypes extracted from a DEX file.
///
/// Maps type indices and proto indices to their decoded representations.
pub struct DexTypeSystem {
    /// `type_id` -> `TypeDescriptor`
    types: Vec<TypeDescriptor>,
    /// `proto_id` -> `MethodProto`
    protos: Vec<MethodProto>,
    /// class descriptor -> `type_id` (reverse lookup)
    class_index: HashMap<String, u32>,
}

impl DexTypeSystem {
    /// Create an empty type system.
    #[must_use]
    pub fn new() -> Self {
        Self {
            types: Vec::new(),
            protos: Vec::new(),
            class_index: HashMap::new(),
        }
    }

    /// Build a type system from raw DEX bytes.
    ///
    /// - `data`: entire DEX file
    /// - `type_ids_offset`, `type_ids_size`: location of type ID list
    /// - `proto_ids_offset`, `proto_ids_size`: location of proto ID list
    /// - `string_pool`: pre-parsed string pool for descriptor lookup
    pub fn from_dex(
        data: &[u8],
        type_ids_offset: u32,
        type_ids_size: u32,
        proto_ids_offset: u32,
        proto_ids_size: u32,
        string_values: &[String],
    ) -> Self {
        // Cap the pre-allocation to what can physically fit in the data buffer,
        // exactly as `dex_string_pool` already does. Each type ID entry is
        // 4 bytes, so the data holds at most `data.len() / 4` of them; without
        // the cap a crafted `type_ids_size = 0xFFFF_FFFF` reserves multiple GB
        // before the first bounds check in the loop is reached.
        let mut types = Vec::with_capacity((type_ids_size as usize).min(data.len() / 4));
        let mut class_index = HashMap::new();

        // Parse type IDs: each is a 4-byte string index
        let tids_off = type_ids_offset as usize;
        for i in 0..type_ids_size as usize {
            let off = tids_off + i * 4;
            if off + 4 > data.len() {
                break;
            }
            let str_idx = u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]]) as usize;
            let descriptor = string_values
                .get(str_idx)
                .map_or("V", String::as_str);
            let td = TypeDescriptor::parse(descriptor).unwrap_or(TypeDescriptor::Primitive(PrimitiveKind::Void));
            if let TypeDescriptor::Class(ref ct) = td {
                class_index.insert(ct.descriptor.clone(), u32::try_from(i).unwrap_or(u32::MAX));
            }
            types.push(td);
        }

        // Parse proto IDs: each is 12 bytes (shorty_idx u32, return_type_idx u32, params_off u32)
        let pids_off = proto_ids_offset as usize;
        // Same cap as the type IDs above; each proto ID entry is 12 bytes.
        let mut protos = Vec::with_capacity((proto_ids_size as usize).min(data.len() / 12));
        for i in 0..proto_ids_size as usize {
            let off = pids_off + i * 12;
            if off + 12 > data.len() {
                break;
            }
            let shorty_idx = u32::from_le_bytes([data[off], data[off+1], data[off+2], data[off+3]]) as usize;
            let return_type_idx = u32::from_le_bytes([data[off+4], data[off+5], data[off+6], data[off+7]]) as usize;
            let params_off = u32::from_le_bytes([data[off+8], data[off+9], data[off+10], data[off+11]]) as usize;

            let shorty = string_values.get(shorty_idx).cloned().unwrap_or_default();
            let return_type = types
                .get(return_type_idx)
                .cloned()
                .unwrap_or(TypeDescriptor::Primitive(PrimitiveKind::Void));

            let mut parameters = Vec::new();
            if params_off != 0 && params_off + 4 <= data.len() {
                let size = u32::from_le_bytes([
                    data[params_off],
                    data[params_off+1],
                    data[params_off+2],
                    data[params_off+3],
                ]) as usize;
                for j in 0..size {
                    let p_off = params_off + 4 + j * 2;
                    if p_off + 2 > data.len() { break; }
                    let type_idx = u16::from_le_bytes([data[p_off], data[p_off+1]]) as usize;
                    if let Some(td) = types.get(type_idx) {
                        parameters.push(td.clone());
                    }
                }
            }

            protos.push(MethodProto::new(shorty, return_type, parameters));
        }

        Self {
            types,
            protos,
            class_index,
        }
    }

    /// Create from pre-built type and proto lists (for testing).
    #[must_use]
    pub fn from_lists(types: Vec<TypeDescriptor>, protos: Vec<MethodProto>) -> Self {
        let mut class_index = HashMap::new();
        for (i, td) in types.iter().enumerate() {
            if let TypeDescriptor::Class(ct) = td {
                class_index.insert(ct.descriptor.clone(), u32::try_from(i).unwrap_or(u32::MAX));
            }
        }
        Self {
            types,
            protos,
            class_index,
        }
    }

    /// Get a type by index.
    #[must_use]
    pub fn get_type(&self, index: usize) -> Option<&TypeDescriptor> {
        self.types.get(index)
    }

    /// Get a proto by index.
    #[must_use]
    pub fn get_proto(&self, index: usize) -> Option<&MethodProto> {
        self.protos.get(index)
    }

    /// Look up a type index by class descriptor.
    #[must_use]
    pub fn find_class_type(&self, descriptor: &str) -> Option<u32> {
        self.class_index.get(descriptor).copied()
    }

    /// All class types in the system.
    #[must_use]
    pub fn all_class_types(&self) -> Vec<&ClassType> {
        self.types
            .iter()
            .filter_map(|td| {
                if let TypeDescriptor::Class(ct) = td {
                    Some(ct)
                } else {
                    None
                }
            })
            .collect()
    }

    /// All array types in the system.
    #[must_use]
    pub fn all_array_types(&self) -> Vec<&TypeDescriptor> {
        self.types
            .iter()
            .filter(|td| matches!(td, TypeDescriptor::Array { .. }))
            .collect()
    }

    /// Total number of types.
    #[must_use]
    pub const fn type_count(&self) -> usize {
        self.types.len()
    }

    /// Total number of method prototypes.
    #[must_use]
    pub const fn proto_count(&self) -> usize {
        self.protos.len()
    }

    /// Find all protos matching a given return type descriptor.
    #[must_use]
    pub fn protos_returning(&self, descriptor: &str) -> Vec<(usize, &MethodProto)> {
        self.protos
            .iter()
            .enumerate()
            .filter(|(_, p)| p.return_type.descriptor() == descriptor)
            .collect()
    }

    /// Count types by category: "primitive", "class", "array".
    #[must_use]
    pub fn type_category_counts(&self) -> HashMap<&'static str, usize> {
        let mut counts = HashMap::new();
        for td in &self.types {
            let cat = match td {
                TypeDescriptor::Primitive(_) => "primitive",
                TypeDescriptor::Class(_) => "class",
                TypeDescriptor::Array { .. } => "array",
            };
            *counts.entry(cat).or_insert(0) += 1;
        }
        counts
    }
}

impl Default for DexTypeSystem {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_primitive_descriptor() {
        assert_eq!(PrimitiveKind::Int.descriptor_char(), 'I');
        assert_eq!(PrimitiveKind::Long.descriptor_char(), 'J');
        assert_eq!(PrimitiveKind::Double.descriptor_char(), 'D');
    }

    #[test]
    fn test_primitive_sizes() {
        assert_eq!(PrimitiveKind::Int.byte_size(), 4);
        assert_eq!(PrimitiveKind::Long.byte_size(), 8);
        assert_eq!(PrimitiveKind::Void.byte_size(), 0);
    }

    #[test]
    fn test_primitive_from_char() {
        assert_eq!(PrimitiveKind::from_char('I'), Some(PrimitiveKind::Int));
        assert_eq!(PrimitiveKind::from_char('X'), None);
    }

    #[test]
    fn test_class_type_parse() {
        let ct = ClassType::from_descriptor("Ljava/lang/String;").unwrap();
        assert_eq!(ct.simple_name(), "String");
        assert_eq!(ct.package_name(), Some("java/lang"));
        assert_eq!(ct.java_name(), "java.lang.String");
        assert!(ct.is_java_lang());
    }

    #[test]
    fn test_class_type_invalid() {
        assert!(ClassType::from_descriptor("java/lang/String").is_none());
        assert!(ClassType::from_descriptor("I").is_none());
    }

    #[test]
    fn test_type_descriptor_primitive() {
        let td = TypeDescriptor::parse("I").unwrap();
        assert_eq!(td.descriptor(), "I");
        assert!(!td.is_void());
        assert!(!td.is_reference());
    }

    #[test]
    fn test_type_descriptor_class() {
        let td = TypeDescriptor::parse("Ljava/lang/Object;").unwrap();
        assert_eq!(td.descriptor(), "Ljava/lang/Object;");
        assert!(td.is_reference());
    }

    #[test]
    fn test_type_descriptor_array() {
        let td = TypeDescriptor::parse("[I").unwrap();
        assert_eq!(td.descriptor(), "[I");
        assert!(td.is_reference());
        if let TypeDescriptor::Array { dimensions, element } = &td {
            assert_eq!(*dimensions, 1);
            assert_eq!(element.descriptor(), "I");
        } else {
            panic!("Expected array");
        }
    }

    #[test]
    fn test_type_descriptor_multidim_array() {
        let td = TypeDescriptor::parse("[[Ljava/lang/String;").unwrap();
        assert_eq!(td.descriptor(), "[[Ljava/lang/String;");
        if let TypeDescriptor::Array { dimensions, .. } = td {
            assert_eq!(dimensions, 2);
        } else {
            panic!("Expected array");
        }
    }

    #[test]
    fn test_method_proto() {
        let proto = MethodProto::new(
            "VIL",
            TypeDescriptor::Primitive(PrimitiveKind::Void),
            vec![
                TypeDescriptor::Primitive(PrimitiveKind::Int),
                TypeDescriptor::parse("Ljava/lang/String;").unwrap(),
            ],
        );
        assert!(proto.returns_void());
        assert_eq!(proto.parameter_register_count(), 2);
        assert_eq!(proto.dex_descriptor(), "(ILjava/lang/String;)V");
    }

    #[test]
    fn test_type_system_from_lists() {
        let types = vec![
            TypeDescriptor::Primitive(PrimitiveKind::Int),
            TypeDescriptor::parse("Ljava/lang/Object;").unwrap(),
        ];
        let protos = vec![MethodProto::new(
            "V",
            TypeDescriptor::Primitive(PrimitiveKind::Void),
            vec![],
        )];
        let ts = DexTypeSystem::from_lists(types, protos);
        assert_eq!(ts.type_count(), 2);
        assert_eq!(ts.proto_count(), 1);
        assert!(ts.find_class_type("Ljava/lang/Object;").is_some());
    }

    #[test]
    fn test_type_category_counts() {
        let types = vec![
            TypeDescriptor::Primitive(PrimitiveKind::Int),
            TypeDescriptor::Primitive(PrimitiveKind::Long),
            TypeDescriptor::parse("Ljava/lang/Object;").unwrap(),
            TypeDescriptor::parse("[I").unwrap(),
        ];
        let ts = DexTypeSystem::from_lists(types, vec![]);
        let counts = ts.type_category_counts();
        assert_eq!(*counts.get("primitive").unwrap(), 2);
        assert_eq!(*counts.get("class").unwrap(), 1);
        assert_eq!(*counts.get("array").unwrap(), 1);
    }

    #[test]
    fn test_protos_returning() {
        let types = vec![];
        let protos = vec![
            MethodProto::new("V", TypeDescriptor::Primitive(PrimitiveKind::Void), vec![]),
            MethodProto::new("I", TypeDescriptor::Primitive(PrimitiveKind::Int), vec![]),
            MethodProto::new("V", TypeDescriptor::Primitive(PrimitiveKind::Void), vec![
                TypeDescriptor::Primitive(PrimitiveKind::Int),
            ]),
        ];
        let ts = DexTypeSystem::from_lists(types, protos);
        let void_protos = ts.protos_returning("V");
        assert_eq!(void_protos.len(), 2);
    }
}
