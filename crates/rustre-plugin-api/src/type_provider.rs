// rustre-plugin-api/src/type_provider.rs
// Type provider plugin sub-API: TypeDefinition, FieldDef, TypeLibrary, BuiltinTypesProvider.

use std::collections::HashMap;

use crate::{Plugin, PluginError, PluginResult};

// ─── Type Reference ──────────────────────────────────────────────────────────

/// A reference to another type by name or by numeric ID.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TypeRef {
    Named(String),
    ById(u32),
    Ptr {
        inner: Box<Self>,
        const_: bool,
    },
    Array {
        inner: Box<Self>,
        count: Option<usize>,
    },
    Fn {
        ret: Box<Self>,
        params: Vec<Self>,
    },
    Void,
    Unknown,
}

impl TypeRef {
    #[must_use]
    pub fn named(name: &str) -> Self {
        Self::Named(name.to_string())
    }
    #[must_use]
    pub const fn by_id(id: u32) -> Self {
        Self::ById(id)
    }
    #[must_use]
    pub fn ptr(inner: Self) -> Self {
        Self::Ptr {
            inner: Box::new(inner),
            const_: false,
        }
    }
    #[must_use]
    pub fn const_ptr(inner: Self) -> Self {
        Self::Ptr {
            inner: Box::new(inner),
            const_: true,
        }
    }
    #[must_use]
    pub fn array(inner: Self, count: Option<usize>) -> Self {
        Self::Array {
            inner: Box::new(inner),
            count,
        }
    }
    #[must_use]
    pub const fn void() -> Self {
        Self::Void
    }

    #[must_use]
    pub const fn is_pointer(&self) -> bool {
        matches!(self, Self::Ptr { .. })
    }
    #[must_use]
    pub const fn is_array(&self) -> bool {
        matches!(self, Self::Array { .. })
    }
    #[must_use]
    pub const fn is_void(&self) -> bool {
        matches!(self, Self::Void)
    }
}

impl std::fmt::Display for TypeRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Named(n) => write!(f, "{n}"),
            Self::ById(id) => write!(f, "<type#{id}>"),
            Self::Ptr { inner, const_ } => {
                write!(f, "{}{}*", if *const_ { "const " } else { "" }, inner)
            }
            Self::Array { inner, count } => match count {
                Some(n) => write!(f, "{inner}[{n}]"),
                None => write!(f, "{inner}[]"),
            },
            Self::Fn { ret, params } => {
                let ps: Vec<String> = params
                    .iter()
                    .map(std::string::ToString::to_string)
                    .collect();
                write!(f, "fn({}) -> {}", ps.join(", "), ret)
            }
            Self::Void => write!(f, "void"),
            Self::Unknown => write!(f, "?"),
        }
    }
}

// ─── Field Definition ────────────────────────────────────────────────────────

/// A single field / member of a struct, union, or enum.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldDef {
    /// Field name (may be empty for anonymous/padding fields).
    pub name: String,
    /// Byte offset within the containing type.
    pub offset: usize,
    /// Type of this field.
    pub type_ref: TypeRef,
    /// Bit-field size in bits (0 = not a bit-field).
    pub bit_size: usize,
    /// Compiler-reported alignment in bytes (0 = unknown).
    pub alignment: usize,
    /// Optional comment / annotation.
    pub comment: String,
}

impl FieldDef {
    #[must_use]
    pub fn new(name: &str, offset: usize, type_ref: TypeRef) -> Self {
        Self {
            name: name.to_string(),
            offset,
            type_ref,
            bit_size: 0,
            alignment: 0,
            comment: String::new(),
        }
    }

    #[must_use]
    pub fn with_comment(mut self, c: &str) -> Self {
        self.comment = c.to_string();
        self
    }
    #[must_use]
    pub const fn with_alignment(mut self, a: usize) -> Self {
        self.alignment = a;
        self
    }
    #[must_use]
    pub const fn with_bit_size(mut self, b: usize) -> Self {
        self.bit_size = b;
        self
    }

    /// True for padding / unnamed fields.
    #[must_use]
    pub const fn is_padding(&self) -> bool {
        self.name.is_empty()
    }
}

// ─── Type Kind ───────────────────────────────────────────────────────────────

/// Discriminates the kind of a `TypeDefinition`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TypeKind {
    Struct,
    Union,
    Enum {
        width: usize,
    },
    Typedef {
        target: TypeRef,
    },
    Function {
        ret: TypeRef,
        params: Vec<(String, TypeRef)>,
    },
    Scalar {
        width: usize,
        signed: bool,
        floating: bool,
    },
    Opaque,
}

// ─── Type Definition ─────────────────────────────────────────────────────────

/// A complete type definition.
#[derive(Debug, Clone)]
pub struct TypeDefinition {
    pub id: u32,
    pub name: String,
    pub kind: TypeKind,
    /// Fields (for struct/union/enum).
    pub fields: Vec<FieldDef>,
    /// Size in bytes (0 = unknown / opaque).
    pub size_bytes: usize,
    /// Required alignment in bytes (0 = unknown).
    pub alignment: usize,
    /// Source library name.
    pub library: String,
    /// Optional comment.
    pub comment: String,
    /// Arbitrary key/value metadata.
    pub metadata: HashMap<String, String>,
}

impl TypeDefinition {
    #[must_use]
    pub fn new(id: u32, name: &str, kind: TypeKind) -> Self {
        Self {
            id,
            name: name.to_string(),
            kind,
            fields: Vec::new(),
            size_bytes: 0,
            alignment: 0,
            library: String::new(),
            comment: String::new(),
            metadata: HashMap::new(),
        }
    }

    #[must_use]
    pub const fn with_size(mut self, sz: usize) -> Self {
        self.size_bytes = sz;
        self
    }
    #[must_use]
    pub const fn with_alignment(mut self, a: usize) -> Self {
        self.alignment = a;
        self
    }
    #[must_use]
    pub fn with_library(mut self, lib: &str) -> Self {
        self.library = lib.to_string();
        self
    }
    #[must_use]
    pub fn with_comment(mut self, c: &str) -> Self {
        self.comment = c.to_string();
        self
    }

    pub fn add_field(&mut self, field: FieldDef) {
        self.fields.push(field);
    }

    #[must_use]
    pub fn field_by_name(&self, name: &str) -> Option<&FieldDef> {
        self.fields.iter().find(|f| f.name == name)
    }

    #[must_use]
    pub fn is_struct(&self) -> bool {
        self.kind == TypeKind::Struct
    }
    #[must_use]
    pub fn is_union(&self) -> bool {
        self.kind == TypeKind::Union
    }
    #[must_use]
    pub fn is_opaque(&self) -> bool {
        self.kind == TypeKind::Opaque
    }
}

// ─── TypeProviderPlugin Trait ─────────────────────────────────────────────────

pub trait TypeProviderPlugin: Plugin {
    /// Retrieve a type by name; returns `None` if not found.
    fn get_type_by_name(&self, name: &str) -> Option<TypeDefinition>;

    /// Retrieve a type by numeric ID.
    fn get_type_by_id(&self, id: u32) -> Option<TypeDefinition>;

    /// List all type names provided by this plugin.
    fn list_types(&self) -> Vec<String>;

    ///
    /// # Errors
    ///
    /// Returns an error if the type cannot be added (e.g. duplicate name).
    fn add_type(&mut self, def: TypeDefinition) -> PluginResult<()>;

    ///
    /// # Errors
    ///
    /// Returns an error if the type cannot be updated.
    fn update_type(&mut self, def: TypeDefinition) -> PluginResult<()>;

    ///
    /// # Errors
    ///
    /// Returns an error if the type does not exist.
    fn remove_type(&mut self, name: &str) -> PluginResult<()>;

    /// Number of types provided.
    fn type_count(&self) -> usize;
}

// ─── TypeLibrary ─────────────────────────────────────────────────────────────

/// A named, versioned collection of type definitions.
#[derive(Debug, Clone)]
pub struct TypeLibrary {
    pub name: String,
    pub version: String,
    pub description: String,
    types_by_name: HashMap<String, TypeDefinition>,
    types_by_id: HashMap<u32, String>,
    next_id: u32,
}

impl TypeLibrary {
    #[must_use]
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            version: "0.1.0".to_string(),
            description: String::new(),
            types_by_name: HashMap::new(),
            types_by_id: HashMap::new(),
            next_id: 1,
        }
    }

    #[must_use]
    pub fn with_version(mut self, v: &str) -> Self {
        self.version = v.to_string();
        self
    }
    #[must_use]
    pub fn with_description(mut self, d: &str) -> Self {
        self.description = d.to_string();
        self
    }

    ///
    /// # Errors
    ///
    /// Returns an error if a type with the same name is already registered.
    pub fn insert(&mut self, mut def: TypeDefinition) -> PluginResult<u32> {
        if def.id == 0 {
            def.id = self.next_id;
            self.next_id += 1;
        }
        if self.types_by_name.contains_key(&def.name) {
            return Err(PluginError::AlreadyRegistered(def.name));
        }
        let id = def.id;
        self.types_by_id.insert(id, def.name.clone());
        self.types_by_name.insert(def.name.clone(), def);
        Ok(id)
    }

    ///
    /// # Errors
    ///
    /// Returns an error if no type with that name exists.
    pub fn update(&mut self, def: TypeDefinition) -> PluginResult<()> {
        if !self.types_by_name.contains_key(&def.name) {
            return Err(PluginError::NotFound(def.name));
        }
        let id = def.id;
        self.types_by_id.insert(id, def.name.clone());
        self.types_by_name.insert(def.name.clone(), def);
        Ok(())
    }

    /// Get by name.
    #[must_use]
    pub fn get_by_name(&self, name: &str) -> Option<&TypeDefinition> {
        self.types_by_name.get(name)
    }

    /// Get by ID.
    #[must_use]
    pub fn get_by_id(&self, id: u32) -> Option<&TypeDefinition> {
        let name = self.types_by_id.get(&id)?;
        self.types_by_name.get(name)
    }

    ///
    /// # Errors
    ///
    /// Returns an error if no type with that name exists.
    pub fn remove(&mut self, name: &str) -> PluginResult<()> {
        let def = self
            .types_by_name
            .remove(name)
            .ok_or_else(|| PluginError::NotFound(name.to_string()))?;
        self.types_by_id.remove(&def.id);
        Ok(())
    }

    #[must_use]
    pub fn list_names(&self) -> Vec<&str> {
        self.types_by_name
            .keys()
            .map(std::string::String::as_str)
            .collect()
    }

    #[must_use]
    pub fn count(&self) -> usize {
        self.types_by_name.len()
    }

    /// Merge `other` into `self`; conflicting names are skipped.
    pub fn merge(&mut self, other: &Self) {
        for def in other.types_by_name.values() {
            if !self.types_by_name.contains_key(&def.name) {
                let _ = self.insert(def.clone());
            }
        }
    }
}

// ─── TypeLibraryManager ──────────────────────────────────────────────────────

/// Manages multiple `TypeLibrary` instances and provides merged lookup.
pub struct TypeLibraryManager {
    libraries: Vec<TypeLibrary>,
    priority: Vec<String>,
}

impl TypeLibraryManager {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            libraries: Vec::new(),
            priority: Vec::new(),
        }
    }

    /// Add a library at the lowest priority.
    pub fn add_library(&mut self, lib: TypeLibrary) {
        self.priority.push(lib.name.clone());
        self.libraries.push(lib);
    }

    /// Add a library at the highest priority.
    pub fn add_library_high_priority(&mut self, lib: TypeLibrary) {
        self.priority.insert(0, lib.name.clone());
        self.libraries.insert(0, lib);
    }

    /// Look up a type by name across all libraries, highest priority first.
    #[must_use]
    pub fn lookup_by_name(&self, name: &str) -> Option<&TypeDefinition> {
        for lib_name in &self.priority {
            if let Some(lib) = self.libraries.iter().find(|l| &l.name == lib_name)
                && let Some(def) = lib.get_by_name(name)
            {
                return Some(def);
            }
        }
        None
    }

    /// Look up by numeric ID across all libraries.
    #[must_use]
    pub fn lookup_by_id(&self, id: u32) -> Option<&TypeDefinition> {
        for lib in &self.libraries {
            if let Some(def) = lib.get_by_id(id) {
                return Some(def);
            }
        }
        None
    }

    /// Return all type names across all libraries (de-duplicated).
    #[must_use]
    pub fn all_names(&self) -> Vec<String> {
        let mut names = std::collections::HashSet::new();
        for lib in &self.libraries {
            for n in lib.list_names() {
                names.insert(n.to_string());
            }
        }
        let mut v: Vec<String> = names.into_iter().collect();
        v.sort();
        v
    }

    /// Merge all managed libraries into a single `TypeLibrary`.
    #[must_use]
    pub fn merge_all(&self, merged_name: &str) -> TypeLibrary {
        let mut result = TypeLibrary::new(merged_name);
        for lib in &self.libraries {
            result.merge(lib);
        }
        result
    }

    #[must_use]
    pub const fn library_count(&self) -> usize {
        self.libraries.len()
    }

    #[must_use]
    pub fn get_library(&self, name: &str) -> Option<&TypeLibrary> {
        self.libraries.iter().find(|l| l.name == name)
    }

    pub fn remove_library(&mut self, name: &str) {
        self.libraries.retain(|l| l.name != name);
        self.priority.retain(|n| n != name);
    }
}

impl Default for TypeLibraryManager {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Builtin Types Provider ──────────────────────────────────────────────────

/// Pre-populates a `TypeLibrary` with common C/C++ primitive types.
pub struct BuiltinTypesProvider;

impl BuiltinTypesProvider {
    /// Build the standard 32-bit or 64-bit builtin library.
    #[must_use]
    pub fn build(ptr_size: usize) -> TypeLibrary {
        let mut lib = TypeLibrary::new("builtins").with_description("Standard C primitive types");

        let scalar = |w: usize, signed: bool, floating: bool| TypeKind::Scalar {
            width: w,
            signed,
            floating,
        };

        let types: &[(&str, TypeKind, usize)] = &[
            ("void", TypeKind::Opaque, 0),
            ("bool", scalar(1, false, false), 1),
            ("u8", scalar(1, false, false), 1),
            ("u16", scalar(2, false, false), 2),
            ("u32", scalar(4, false, false), 4),
            ("u64", scalar(8, false, false), 8),
            ("u128", scalar(16, false, false), 16),
            ("i8", scalar(1, true, false), 1),
            ("i16", scalar(2, true, false), 2),
            ("i32", scalar(4, true, false), 4),
            ("i64", scalar(8, true, false), 8),
            ("i128", scalar(16, true, false), 16),
            ("f32", scalar(4, true, true), 4),
            ("f64", scalar(8, true, true), 8),
            ("f128", scalar(16, true, true), 16),
            ("char", scalar(1, false, false), 1),
            ("wchar_t", scalar(2, false, false), 2),
            ("size_t", scalar(ptr_size, false, false), ptr_size),
            ("ssize_t", scalar(ptr_size, true, false), ptr_size),
            ("uintptr_t", scalar(ptr_size, false, false), ptr_size),
            ("intptr_t", scalar(ptr_size, true, false), ptr_size),
            // Pointer-to-void.
            (
                "void*",
                TypeKind::Typedef {
                    target: TypeRef::ptr(TypeRef::void()),
                },
                ptr_size,
            ),
        ];

        for (name, kind, size) in types {
            let def = TypeDefinition::new(0, name, kind.clone())
                .with_size(*size)
                .with_library("builtins");
            let _ = lib.insert(def);
        }
        lib
    }

    /// Return just the void type.
    #[must_use]
    pub fn void_type() -> TypeDefinition {
        TypeDefinition::new(0, "void", TypeKind::Opaque)
    }

    /// Return a builtin scalar.
    #[must_use]
    pub fn scalar(name: &str, width: usize, signed: bool) -> TypeDefinition {
        TypeDefinition::new(
            0,
            name,
            TypeKind::Scalar {
                width,
                signed,
                floating: false,
            },
        )
        .with_size(width)
    }

    /// Return a builtin float.
    #[must_use]
    pub fn float(name: &str, width: usize) -> TypeDefinition {
        TypeDefinition::new(
            0,
            name,
            TypeKind::Scalar {
                width,
                signed: true,
                floating: true,
            },
        )
        .with_size(width)
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── TypeRef ──────────────────────────────────────────────────────────

    #[test]
    fn test_type_ref_named() {
        let t = TypeRef::named("MyStruct");
        assert_eq!(t.to_string(), "MyStruct");
    }

    #[test]
    fn test_type_ref_ptr() {
        let t = TypeRef::ptr(TypeRef::named("u8"));
        assert!(t.is_pointer());
        assert!(t.to_string().contains("u8"));
        assert!(t.to_string().contains('*'));
    }

    #[test]
    fn test_type_ref_const_ptr() {
        let t = TypeRef::const_ptr(TypeRef::named("char"));
        assert!(t.to_string().contains("const"));
    }

    #[test]
    fn test_type_ref_array() {
        let t = TypeRef::array(TypeRef::named("u32"), Some(10));
        assert!(t.is_array());
        assert!(t.to_string().contains("10"));
    }

    #[test]
    fn test_type_ref_array_unsized() {
        let t = TypeRef::array(TypeRef::named("u8"), None);
        assert!(t.to_string().contains("[]"));
    }

    #[test]
    fn test_type_ref_void() {
        let t = TypeRef::void();
        assert!(t.is_void());
        assert_eq!(t.to_string(), "void");
    }

    #[test]
    fn test_type_ref_fn() {
        let t = TypeRef::Fn {
            ret: Box::new(TypeRef::named("i32")),
            params: vec![TypeRef::named("u8"), TypeRef::named("u32")],
        };
        let s = t.to_string();
        assert!(s.contains("fn("));
        assert!(s.contains("i32"));
    }

    // ── FieldDef ──────────────────────────────────────────────────────────

    #[test]
    fn test_field_def_new() {
        let f = FieldDef::new("x", 4, TypeRef::named("i32"));
        assert_eq!(f.name, "x");
        assert_eq!(f.offset, 4);
        assert!(!f.is_padding());
    }

    #[test]
    fn test_field_def_padding() {
        let f = FieldDef::new("", 0, TypeRef::named("u8"));
        assert!(f.is_padding());
    }

    #[test]
    fn test_field_def_builder() {
        let f = FieldDef::new("flags", 0, TypeRef::named("u32"))
            .with_comment("bitflags")
            .with_alignment(4);
        assert_eq!(f.comment, "bitflags");
        assert_eq!(f.alignment, 4);
    }

    // ── TypeDefinition ────────────────────────────────────────────────────

    #[test]
    fn test_type_definition_new() {
        let t = TypeDefinition::new(1, "Foo", TypeKind::Struct);
        assert_eq!(t.name, "Foo");
        assert!(t.is_struct());
    }

    #[test]
    fn test_type_definition_add_field() {
        let mut t = TypeDefinition::new(1, "Point", TypeKind::Struct).with_size(8);
        t.add_field(FieldDef::new("x", 0, TypeRef::named("i32")));
        t.add_field(FieldDef::new("y", 4, TypeRef::named("i32")));
        assert_eq!(t.fields.len(), 2);
        assert!(t.field_by_name("x").is_some());
        assert!(t.field_by_name("z").is_none());
    }

    #[test]
    fn test_type_definition_builder() {
        let t = TypeDefinition::new(0, "T", TypeKind::Opaque)
            .with_size(16)
            .with_alignment(8)
            .with_library("mylib")
            .with_comment("opaque forward decl");
        assert_eq!(t.size_bytes, 16);
        assert_eq!(t.alignment, 8);
        assert_eq!(t.library, "mylib");
    }

    // ── TypeLibrary ───────────────────────────────────────────────────────

    #[test]
    fn test_library_insert_get() {
        let mut lib = TypeLibrary::new("test");
        let def = TypeDefinition::new(0, "MyType", TypeKind::Struct);
        lib.insert(def).unwrap();
        assert!(lib.get_by_name("MyType").is_some());
    }

    #[test]
    fn test_library_insert_duplicate_fails() {
        let mut lib = TypeLibrary::new("test");
        lib.insert(TypeDefinition::new(0, "T", TypeKind::Struct))
            .unwrap();
        let err = lib.insert(TypeDefinition::new(0, "T", TypeKind::Struct));
        assert!(err.is_err());
    }

    #[test]
    fn test_library_get_by_id() {
        let mut lib = TypeLibrary::new("test");
        let id = lib
            .insert(TypeDefinition::new(0, "T", TypeKind::Struct))
            .unwrap();
        assert!(lib.get_by_id(id).is_some());
    }

    #[test]
    fn test_library_update() {
        let mut lib = TypeLibrary::new("test");
        lib.insert(TypeDefinition::new(0, "T", TypeKind::Struct))
            .unwrap();
        let updated = TypeDefinition::new(1, "T", TypeKind::Union);
        assert!(lib.update(updated).is_ok());
        assert!(lib.get_by_name("T").unwrap().is_union());
    }

    #[test]
    fn test_library_update_not_found() {
        let mut lib = TypeLibrary::new("test");
        let err = lib.update(TypeDefinition::new(1, "Ghost", TypeKind::Struct));
        assert!(err.is_err());
    }

    #[test]
    fn test_library_remove() {
        let mut lib = TypeLibrary::new("test");
        lib.insert(TypeDefinition::new(0, "T", TypeKind::Struct))
            .unwrap();
        lib.remove("T").unwrap();
        assert!(lib.get_by_name("T").is_none());
        assert_eq!(lib.count(), 0);
    }

    #[test]
    fn test_library_remove_not_found() {
        let mut lib = TypeLibrary::new("test");
        assert!(lib.remove("Nonexistent").is_err());
    }

    #[test]
    fn test_library_list_names() {
        let mut lib = TypeLibrary::new("test");
        lib.insert(TypeDefinition::new(0, "A", TypeKind::Struct))
            .unwrap();
        lib.insert(TypeDefinition::new(0, "B", TypeKind::Struct))
            .unwrap();
        let names = lib.list_names();
        assert_eq!(names.len(), 2);
        assert!(names.contains(&"A"));
        assert!(names.contains(&"B"));
    }

    #[test]
    fn test_library_merge() {
        let mut lib1 = TypeLibrary::new("lib1");
        lib1.insert(TypeDefinition::new(0, "A", TypeKind::Struct))
            .unwrap();
        let mut lib2 = TypeLibrary::new("lib2");
        lib2.insert(TypeDefinition::new(0, "B", TypeKind::Struct))
            .unwrap();
        lib2.insert(TypeDefinition::new(0, "A", TypeKind::Union))
            .unwrap(); // conflict

        lib1.merge(&lib2);
        assert!(lib1.get_by_name("B").is_some());
        // A should still be struct (lib1's version wins)
        assert!(lib1.get_by_name("A").unwrap().is_struct());
        assert_eq!(lib1.count(), 2);
    }

    // ── TypeLibraryManager ───────────────────────────────────────────────

    #[test]
    fn test_manager_add_lookup() {
        let mut mgr = TypeLibraryManager::new();
        let mut lib = TypeLibrary::new("stdlib");
        lib.insert(TypeDefinition::new(
            0,
            "size_t",
            TypeKind::Scalar {
                width: 8,
                signed: false,
                floating: false,
            },
        ))
        .unwrap();
        mgr.add_library(lib);
        assert!(mgr.lookup_by_name("size_t").is_some());
        assert!(mgr.lookup_by_name("unknown_xyz").is_none());
    }

    #[test]
    fn test_manager_priority() {
        let mut mgr = TypeLibraryManager::new();
        let mut low = TypeLibrary::new("low");
        low.insert(TypeDefinition::new(0, "T", TypeKind::Struct))
            .unwrap();
        let mut high = TypeLibrary::new("high");
        high.insert(TypeDefinition::new(0, "T", TypeKind::Union))
            .unwrap();

        mgr.add_library(low);
        mgr.add_library_high_priority(high);

        // high-priority library should win
        let found = mgr.lookup_by_name("T").unwrap();
        assert!(found.is_union());
    }

    #[test]
    fn test_manager_all_names() {
        let mut mgr = TypeLibraryManager::new();
        let mut a = TypeLibrary::new("a");
        a.insert(TypeDefinition::new(0, "X", TypeKind::Struct))
            .unwrap();
        let mut b = TypeLibrary::new("b");
        b.insert(TypeDefinition::new(0, "Y", TypeKind::Struct))
            .unwrap();
        b.insert(TypeDefinition::new(0, "X", TypeKind::Struct))
            .unwrap(); // duplicate

        mgr.add_library(a);
        mgr.add_library(b);

        let names = mgr.all_names();
        assert_eq!(names.len(), 2); // deduped
    }

    #[test]
    fn test_manager_merge_all() {
        let mut mgr = TypeLibraryManager::new();
        let mut a = TypeLibrary::new("a");
        a.insert(TypeDefinition::new(0, "X", TypeKind::Struct))
            .unwrap();
        let mut b = TypeLibrary::new("b");
        b.insert(TypeDefinition::new(0, "Y", TypeKind::Struct))
            .unwrap();
        mgr.add_library(a);
        mgr.add_library(b);

        let merged = mgr.merge_all("all");
        assert!(merged.get_by_name("X").is_some());
        assert!(merged.get_by_name("Y").is_some());
    }

    #[test]
    fn test_manager_remove_library() {
        let mut mgr = TypeLibraryManager::new();
        let mut lib = TypeLibrary::new("removable");
        lib.insert(TypeDefinition::new(0, "Z", TypeKind::Struct))
            .unwrap();
        mgr.add_library(lib);
        assert_eq!(mgr.library_count(), 1);
        mgr.remove_library("removable");
        assert_eq!(mgr.library_count(), 0);
        assert!(mgr.lookup_by_name("Z").is_none());
    }

    // ── BuiltinTypesProvider ──────────────────────────────────────────────

    #[test]
    fn test_builtin_build_64() {
        let lib = BuiltinTypesProvider::build(8);
        assert!(lib.get_by_name("void").is_some());
        assert!(lib.get_by_name("u8").is_some());
        assert!(lib.get_by_name("i64").is_some());
        assert!(lib.get_by_name("f32").is_some());
        assert!(lib.get_by_name("char").is_some());
        assert!(lib.get_by_name("void*").is_some());
    }

    #[test]
    fn test_builtin_build_32() {
        let lib = BuiltinTypesProvider::build(4);
        let size_t = lib.get_by_name("size_t").unwrap();
        assert_eq!(size_t.size_bytes, 4);
    }

    #[test]
    fn test_builtin_scalar_sizes() {
        let lib = BuiltinTypesProvider::build(8);
        assert_eq!(lib.get_by_name("u8").unwrap().size_bytes, 1);
        assert_eq!(lib.get_by_name("u16").unwrap().size_bytes, 2);
        assert_eq!(lib.get_by_name("u32").unwrap().size_bytes, 4);
        assert_eq!(lib.get_by_name("u64").unwrap().size_bytes, 8);
    }

    #[test]
    fn test_builtin_float_sizes() {
        let lib = BuiltinTypesProvider::build(8);
        assert_eq!(lib.get_by_name("f32").unwrap().size_bytes, 4);
        assert_eq!(lib.get_by_name("f64").unwrap().size_bytes, 8);
    }

    #[test]
    fn test_builtin_void_type() {
        let t = BuiltinTypesProvider::void_type();
        assert_eq!(t.name, "void");
        assert!(t.is_opaque());
    }

    #[test]
    fn test_builtin_scalar_helper() {
        let t = BuiltinTypesProvider::scalar("my_uint", 4, false);
        assert_eq!(t.size_bytes, 4);
        if let TypeKind::Scalar { signed, .. } = t.kind {
            assert!(!signed);
        } else {
            panic!("expected scalar");
        }
    }

    #[test]
    fn test_builtin_float_helper() {
        let t = BuiltinTypesProvider::float("my_float", 8);
        if let TypeKind::Scalar {
            floating, width, ..
        } = t.kind
        {
            assert!(floating);
            assert_eq!(width, 8);
        } else {
            panic!("expected scalar");
        }
    }

    #[test]
    fn test_builtin_all_signed() {
        let lib = BuiltinTypesProvider::build(8);
        for name in &["i8", "i16", "i32", "i64"] {
            let def = lib.get_by_name(name).unwrap();
            if let TypeKind::Scalar { signed, .. } = def.kind {
                assert!(signed, "{name} should be signed");
            }
        }
    }

    #[test]
    fn test_builtin_all_unsigned() {
        let lib = BuiltinTypesProvider::build(8);
        for name in &["u8", "u16", "u32", "u64"] {
            let def = lib.get_by_name(name).unwrap();
            if let TypeKind::Scalar { signed, .. } = def.kind {
                assert!(!signed, "{name} should be unsigned");
            }
        }
    }
}
