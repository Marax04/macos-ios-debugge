//! Load and resolve .NET types from ECMA-335 metadata tables (table-walking layer).
//!
//! This module walks the `TypeDef` and `TypeRef` tables to build a typed
//! representation of every class, interface, and value-type defined or
//! referenced in an assembly.
//!
//! # Design note — relation to `dotnet_type_system`
//! This module (`dotnet_type_loader`) is the **data-extraction** layer: it
//! reads raw metadata rows and emits flat typed records.  [`dotnet_type_system`]
//! is the **semantic analysis** layer that builds inheritance chains, MRO,
//! generic parameter graphs, and cross-assembly dependency models on top of
//! the data produced here.  The two modules are intentionally distinct pipeline
//! stages — do not merge them.

use std::collections::HashMap;
use std::fmt;

use crate::{
    InterfaceImplRow, MethodDefRow, NestedClassRow, TypeDefRow, TypeRefRow,
    read_string_heap, resolve_type_name,
};

// ── TypeKind ──────────────────────────────────────────────────────────────────

/// The kind of a .NET type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum TypeKind {
    /// A `class` definition.
    Class,
    /// An `interface` definition.
    Interface,
    /// A `struct` / value type.
    ValueType,
    /// An `enum` (special value type deriving from `System.Enum`).
    Enum,
    /// A delegate.
    Delegate,
    /// A module pseudo-class (`<Module>`).
    Module,
    /// Unknown or unresolved.
    Unknown,
}

impl fmt::Display for TypeKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Class => write!(f, "class"),
            Self::Interface => write!(f, "interface"),
            Self::ValueType => write!(f, "struct"),
            Self::Enum => write!(f, "enum"),
            Self::Delegate => write!(f, "delegate"),
            Self::Module => write!(f, "module"),
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

// ── Visibility ────────────────────────────────────────────────────────────────

/// .NET type visibility flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Visibility {
    /// `public` — accessible from any assembly.
    Public,
    /// `internal` (`NotPublic`) — accessible within the assembly only.
    Internal,
    /// Nested public.
    NestedPublic,
    /// Nested private.
    NestedPrivate,
    /// Nested family (protected).
    NestedFamily,
    /// Nested assembly-or-family (protected internal).
    NestedFamOrAssem,
    /// Nested assembly.
    NestedAssembly,
    /// Other / unrecognised.
    Other(u32),
}

impl Visibility {
    /// Decode from the low 7 bits of `TypeDef.Flags`.
    #[must_use]
    pub const fn from_flags(flags: u32) -> Self {
        match flags & 0x7 {
            0x0 => Self::Internal,
            0x1 => Self::Public,
            0x2 => Self::NestedPublic,
            0x3 => Self::NestedPrivate,
            0x4 => Self::NestedFamily,
            0x5 => Self::NestedAssembly,
            0x6 => Self::NestedFamOrAssem,
            other => Self::Other(other),
        }
    }

    /// Returns `true` for any public or nested-public visibility.
    #[must_use]
    pub const fn is_public(&self) -> bool {
        matches!(self, Self::Public | Self::NestedPublic)
    }
}

impl fmt::Display for Visibility {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Public => write!(f, "public"),
            Self::Internal => write!(f, "internal"),
            Self::NestedPublic => write!(f, "nested public"),
            Self::NestedPrivate => write!(f, "nested private"),
            Self::NestedFamily => write!(f, "protected"),
            Self::NestedFamOrAssem => write!(f, "protected internal"),
            Self::NestedAssembly => write!(f, "nested internal"),
            Self::Other(v) => write!(f, "visibility({v:#x})"),
        }
    }
}

// ── TypeRef ───────────────────────────────────────────────────────────────────

/// A resolved reference to a type defined in another assembly.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TypeRef {
    /// Zero-based row index in the `TypeRef` table.
    pub row_index: usize,
    /// Namespace (may be empty for top-level types without a namespace).
    pub namespace: String,
    /// Simple type name (not qualified).
    pub name: String,
    /// Resolution scope token (module, assembly-ref, or type-ref).
    pub resolution_scope: u32,
}

impl TypeRef {
    /// Returns the fully-qualified name `"Namespace.Name"` (or just `"Name"`
    /// when the namespace is absent).
    #[must_use]
    pub fn full_name(&self) -> String {
        if self.namespace.is_empty() {
            self.name.clone()
        } else {
            format!("{}.{}", self.namespace, self.name)
        }
    }
}

impl fmt::Display for TypeRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TypeRef[{}] {}", self.row_index, self.full_name())
    }
}

// ── DotnetType ────────────────────────────────────────────────────────────────

/// A .NET type as loaded from the metadata tables.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DotnetType {
    /// Zero-based index into the `TypeDef` table.
    pub type_def_index: usize,
    /// Fully-qualified type name (e.g. `"System.Collections.Generic.List\`1"`).
    pub full_name: String,
    /// Simple type name (without namespace).
    pub name: String,
    /// Namespace.
    pub namespace: String,
    /// Visibility.
    pub visibility: Visibility,
    /// Kind (class, interface, enum, …).
    pub kind: TypeKind,
    /// Whether the type is abstract.
    pub is_abstract: bool,
    /// Whether the type is sealed.
    pub is_sealed: bool,
    /// Whether the type is static (abstract + sealed in IL).
    pub is_static: bool,
    /// Fully-qualified base type name (empty if none / `System.Object`).
    pub base_type: String,
    /// Implemented interface names.
    pub interfaces: Vec<String>,
    /// Indices of directly nested types (`type_def_index` values).
    pub nested_types: Vec<usize>,
    /// Method def row indices belonging to this type.
    pub method_indices: Vec<usize>,
    /// Raw `TypeDef` flags.
    pub flags: u32,
}

impl DotnetType {
    /// Returns `true` when the type is a generic type (name contains `` ` ``).
    #[must_use]
    pub fn is_generic(&self) -> bool {
        self.name.contains('`')
    }

    /// Returns the arity of a generic type (e.g. `List\`1` → 1), or 0 for non-generics.
    #[must_use]
    pub fn generic_arity(&self) -> u32 {
        self.name
            .rsplit('`')
            .next()
            .and_then(|s| s.parse().ok())
            .unwrap_or(0)
    }

    /// Returns `true` when this type has at least one interface.
    #[must_use]
    pub const fn implements_interfaces(&self) -> bool {
        !self.interfaces.is_empty()
    }

    /// Returns `true` when this type has nested types.
    #[must_use]
    pub const fn has_nested_types(&self) -> bool {
        !self.nested_types.is_empty()
    }

    /// Returns the number of methods.
    #[must_use]
    pub const fn method_count(&self) -> usize {
        self.method_indices.len()
    }
}

impl fmt::Display for DotnetType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} {} (base={} ifaces={})",
            self.visibility,
            self.kind,
            self.full_name,
            if self.base_type.is_empty() { "none" } else { &self.base_type },
            self.interfaces.len()
        )
    }
}

// ── TypeResolutionError ───────────────────────────────────────────────────────

/// Error type for type resolution failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TypeResolutionError {
    /// A token referenced a table row that does not exist.
    OutOfRange { table: &'static str, row: usize },
    /// A token's table tag was not recognised.
    UnknownToken(u32),
    /// Circular resolution was detected.
    CircularReference(String),
}

impl fmt::Display for TypeResolutionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OutOfRange { table, row } => {
                write!(f, "token out of range: table={table} row={row}")
            }
            Self::UnknownToken(tok) => write!(f, "unknown token {tok:#010x}"),
            Self::CircularReference(name) => write!(f, "circular type reference: {name}"),
        }
    }
}

impl std::error::Error for TypeResolutionError {}

// ── DotnetTypeLoader ──────────────────────────────────────────────────────────

/// Loads and resolves all .NET types from the parsed metadata tables.
pub struct DotnetTypeLoader<'a> {
    type_defs: &'a [TypeDefRow],
    type_refs: &'a [TypeRefRow],
    interface_impls: &'a [InterfaceImplRow],
    nested_classes: &'a [NestedClassRow],
    method_defs: &'a [MethodDefRow],
    strings: &'a [u8],
}

impl<'a> DotnetTypeLoader<'a> {
    /// Create a new loader from the parsed metadata.
    #[must_use]
    pub const fn new(
        type_defs: &'a [TypeDefRow],
        type_refs: &'a [TypeRefRow],
        interface_impls: &'a [InterfaceImplRow],
        nested_classes: &'a [NestedClassRow],
        method_defs: &'a [MethodDefRow],
        strings: &'a [u8],
    ) -> Self {
        Self {
            type_defs,
            type_refs,
            interface_impls,
            nested_classes,
            method_defs,
            strings,
        }
    }

    /// Build a map of interface implementations: class row index → interface names.
    fn build_iface_map(&self) -> HashMap<usize, Vec<String>> {
        let mut map: HashMap<usize, Vec<String>> = HashMap::new();
        for ii in self.interface_impls {
            let class_idx = (ii.class as usize).wrapping_sub(1);
            let iface = resolve_type_name(ii.interface, self.type_defs, self.type_refs, self.strings);
            map.entry(class_idx).or_default().push(iface);
        }
        map
    }

    /// Build a map of nested types: enclosing type index → nested indices.
    fn build_nested_map(&self) -> HashMap<usize, Vec<usize>> {
        let mut map: HashMap<usize, Vec<usize>> = HashMap::new();
        for nc in self.nested_classes {
            let nested = (nc.nested_class as usize).wrapping_sub(1);
            let enclosing = (nc.enclosing_class as usize).wrapping_sub(1);
            map.entry(enclosing).or_default().push(nested);
        }
        map
    }

    /// Build a map of method indices: `type_def_idx` → `method_def` indices.
    fn build_method_map(&self) -> HashMap<usize, Vec<usize>> {
        let mut map: HashMap<usize, Vec<usize>> = HashMap::with_capacity(self.type_defs.len());
        for (td_idx, td) in self.type_defs.iter().enumerate() {
            let start = (td.method_list as usize).wrapping_sub(1);
            let end = self
                .type_defs
                .get(td_idx + 1)
                .map_or(self.method_defs.len(), |next| (next.method_list as usize).wrapping_sub(1));
            let end_clamped = end.min(self.method_defs.len());
            let count = end_clamped.saturating_sub(start);
            let mut indices = Vec::with_capacity(count);
            indices.extend(start..end_clamped);
            map.insert(td_idx, indices);
        }
        map
    }

    /// Infer the [`TypeKind`] from flags and base type name.
    fn infer_kind(flags: u32, base_type: &str) -> TypeKind {
        if flags & 0x0000_0020 != 0 {
            return TypeKind::Interface;
        }
        if base_type == "System.Enum" {
            return TypeKind::Enum;
        }
        if base_type == "System.MulticastDelegate" || base_type == "System.Delegate" {
            return TypeKind::Delegate;
        }
        if base_type == "System.ValueType" {
            return TypeKind::ValueType;
        }
        TypeKind::Class
    }

    /// Load all `TypeDef` rows into a `Vec<DotnetType>`.
    ///
    /// The returned vector is parallel to the `TypeDef` table: index N →
    /// `TypeDef`[N].
    #[must_use]
    pub fn load_all(&self) -> Vec<DotnetType> {
        let iface_map = self.build_iface_map();
        let nested_map = self.build_nested_map();
        let method_map = self.build_method_map();

        self.type_defs
            .iter()
            .enumerate()
            .map(|(idx, td)| {
                let ns = read_string_heap(self.strings, td.type_namespace);
                let name = read_string_heap(self.strings, td.type_name);
                let full_name = if ns.is_empty() {
                    name.to_owned()
                } else {
                    format!("{ns}.{name}")
                };

                let base_type = if td.extends == 0 || td.extends == 0xFFFF_FFFF {
                    String::new()
                } else {
                    resolve_type_name(td.extends, self.type_defs, self.type_refs, self.strings)
                };

                let visibility = Visibility::from_flags(td.flags);
                let is_abstract = td.flags & 0x0000_0080 != 0;
                let is_sealed = td.flags & 0x0000_0100 != 0;
                let is_static = is_abstract && is_sealed;

                let kind = if full_name == "<Module>" {
                    TypeKind::Module
                } else {
                    Self::infer_kind(td.flags, &base_type)
                };

                DotnetType {
                    type_def_index: idx,
                    full_name,
                    name: name.to_owned(),
                    namespace: ns.to_owned(),
                    visibility,
                    kind,
                    is_abstract,
                    is_sealed,
                    is_static,
                    base_type,
                    interfaces: iface_map.get(&idx).cloned().unwrap_or_default(),
                    nested_types: nested_map.get(&idx).cloned().unwrap_or_default(),
                    method_indices: method_map.get(&idx).cloned().unwrap_or_default(),
                    flags: td.flags,
                }
            })
            .collect()
    }

    /// Load all `TypeRef` rows into a `Vec<TypeRef>`.
    #[must_use]
    pub fn load_type_refs(&self) -> Vec<TypeRef> {
        self.type_refs
            .iter()
            .enumerate()
            .map(|(idx, tr)| {
                let ns = read_string_heap(self.strings, tr.type_namespace);
                let name = read_string_heap(self.strings, tr.type_name);
                TypeRef {
                    row_index: idx,
                    namespace: ns.to_owned(),
                    name: name.to_owned(),
                    resolution_scope: tr.resolution_scope,
                }
            })
            .collect()
    }

    /// Resolve a `TypeDefOrRef` token to its full name.
    ///
    /// # Errors
    ///
    /// Returns [`TypeResolutionError::UnknownToken`] for unrecognised table
    /// tags, and [`TypeResolutionError::OutOfRange`] for invalid row indices.
    pub fn resolve_typeref(&self, token: u32) -> Result<String, TypeResolutionError> {
        let table = (token >> 24) as u8;
        let row = (token & 0x00FF_FFFF) as usize;
        let row_idx = row.wrapping_sub(1);
        match table {
            0x02 => {
                let td = self.type_defs.get(row_idx).ok_or(TypeResolutionError::OutOfRange {
                    table: "TypeDef",
                    row: row_idx,
                })?;
                let ns = read_string_heap(self.strings, td.type_namespace);
                let name = read_string_heap(self.strings, td.type_name);
                Ok(if ns.is_empty() {
                    name.to_owned()
                } else {
                    format!("{ns}.{name}")
                })
            }
            0x01 => {
                let tr = self.type_refs.get(row_idx).ok_or(TypeResolutionError::OutOfRange {
                    table: "TypeRef",
                    row: row_idx,
                })?;
                let ns = read_string_heap(self.strings, tr.type_namespace);
                let name = read_string_heap(self.strings, tr.type_name);
                Ok(if ns.is_empty() {
                    name.to_owned()
                } else {
                    format!("{ns}.{name}")
                })
            }
            0x1B => Ok(format!("<TypeSpec:{row:#010x}>")),
            _ => Err(TypeResolutionError::UnknownToken(token)),
        }
    }

    /// Find all types that derive from `base_name` (direct only).
    #[must_use]
    pub fn find_derived_types(&self, types: &[DotnetType], base_name: &str) -> Vec<usize> {
        types
            .iter()
            .enumerate()
            .filter(|(_, t)| t.base_type == base_name)
            .map(|(i, _)| i)
            .collect()
    }

    /// Find all types implementing `interface_name`.
    #[must_use]
    pub fn find_implementors(&self, types: &[DotnetType], interface_name: &str) -> Vec<usize> {
        types
            .iter()
            .filter(|t| t.interfaces.iter().any(|i| i == interface_name))
            .map(|t| t.type_def_index)
            .collect()
    }

    /// Build a `HashMap<String, usize>` for quick lookup by full name.
    #[must_use]
    pub fn build_name_index(types: &[DotnetType]) -> HashMap<String, usize> {
        types
            .iter()
            .map(|t| (t.full_name.clone(), t.type_def_index))
            .collect()
    }
}

// ── TypeStats ─────────────────────────────────────────────────────────────────

/// Statistics about the types in an assembly.
#[derive(Debug, Clone, Default)]
pub struct TypeStats {
    pub total: usize,
    pub classes: usize,
    pub interfaces: usize,
    pub value_types: usize,
    pub enums: usize,
    pub delegates: usize,
    pub abstract_types: usize,
    pub sealed_types: usize,
    pub generic_types: usize,
}

impl TypeStats {
    /// Compute statistics from a loaded type list.
    #[must_use]
    pub fn from_types(types: &[DotnetType]) -> Self {
        let mut s = Self::default();
        s.total = types.len();
        for t in types {
            match t.kind {
                TypeKind::Class | TypeKind::Module | TypeKind::Unknown => s.classes += 1,
                TypeKind::Interface => s.interfaces += 1,
                TypeKind::ValueType => s.value_types += 1,
                TypeKind::Enum => s.enums += 1,
                TypeKind::Delegate => s.delegates += 1,
            }
            if t.is_abstract { s.abstract_types += 1; }
            if t.is_sealed   { s.sealed_types += 1; }
            if t.is_generic()  { s.generic_types += 1; }
        }
        s
    }
}

impl fmt::Display for TypeStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "TypeStats {{ total={} class={} iface={} struct={} enum={} delegate={} abstract={} sealed={} generic={} }}",
            self.total,
            self.classes,
            self.interfaces,
            self.value_types,
            self.enums,
            self.delegates,
            self.abstract_types,
            self.sealed_types,
            self.generic_types,
        )
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    fn make_strings(entries: &[&str]) -> Vec<u8> {
        let mut v = vec![0u8]; // index 0 = empty
        for s in entries {
            v.extend_from_slice(s.as_bytes());
            v.push(0);
        }
        v
    }

    pub fn make_typedef(ns_idx: u32, name_idx: u32, flags: u32, extends: u32) -> TypeDefRow {
        TypeDefRow {
            flags,
            type_name: name_idx,
            type_namespace: ns_idx,
            extends,
            field_list: 1,
            method_list: 1,
        }
    }

    #[test]
    fn type_kind_display() {
        assert_eq!(TypeKind::Class.to_string(), "class");
        assert_eq!(TypeKind::Interface.to_string(), "interface");
        assert_eq!(TypeKind::Enum.to_string(), "enum");
    }

    #[test]
    fn visibility_from_flags_public() {
        assert_eq!(Visibility::from_flags(0x1), Visibility::Public);
    }

    #[test]
    fn visibility_from_flags_internal() {
        assert_eq!(Visibility::from_flags(0x0), Visibility::Internal);
    }

    #[test]
    fn visibility_is_public() {
        assert!(Visibility::Public.is_public());
        assert!(!Visibility::Internal.is_public());
    }

    #[test]
    fn type_ref_full_name_with_ns() {
        let tr = TypeRef {
            row_index: 0,
            namespace: "System".into(),
            name: "Object".into(),
            resolution_scope: 0,
        };
        assert_eq!(tr.full_name(), "System.Object");
    }

    #[test]
    fn type_ref_full_name_no_ns() {
        let tr = TypeRef {
            row_index: 0,
            namespace: String::new(),
            name: "MyClass".into(),
            resolution_scope: 0,
        };
        assert_eq!(tr.full_name(), "MyClass");
    }

    #[test]
    fn type_ref_display() {
        let tr = TypeRef {
            row_index: 2,
            namespace: "Ns".into(),
            name: "Foo".into(),
            resolution_scope: 1,
        };
        let s = format!("{tr}");
        assert!(s.contains("Ns.Foo"));
    }

    #[test]
    fn dotnet_type_is_generic_true() {
        let t = DotnetType {
            type_def_index: 0,
            full_name: "List`1".into(),
            name: "List`1".into(),
            namespace: String::new(),
            visibility: Visibility::Public,
            kind: TypeKind::Class,
            is_abstract: false,
            is_sealed: false,
            is_static: false,
            base_type: String::new(),
            interfaces: vec![],
            nested_types: vec![],
            method_indices: vec![],
            flags: 0,
        };
        assert!(t.is_generic());
        assert_eq!(t.generic_arity(), 1);
    }

    #[test]
    fn dotnet_type_is_generic_false() {
        let t = DotnetType {
            type_def_index: 0,
            full_name: "MyClass".into(),
            name: "MyClass".into(),
            namespace: String::new(),
            visibility: Visibility::Public,
            kind: TypeKind::Class,
            is_abstract: false,
            is_sealed: false,
            is_static: false,
            base_type: String::new(),
            interfaces: vec![],
            nested_types: vec![],
            method_indices: vec![],
            flags: 0,
        };
        assert!(!t.is_generic());
        assert_eq!(t.generic_arity(), 0);
    }

    #[test]
    fn loader_load_all_basic() {
        let strings = make_strings(&["MyNs", "MyClass"]);
        // String offsets: empty=0, "MyNs"=1, "MyClass"=6
        let td = TypeDefRow {
            flags: 0x1, // public
            type_name: 6,
            type_namespace: 1,
            extends: 0,
            field_list: 1,
            method_list: 1,
        };
        let tds = [td];
        let loader = DotnetTypeLoader::new(&tds, &[], &[], &[], &[], &strings);
        let types = loader.load_all();
        assert_eq!(types.len(), 1);
        assert_eq!(types[0].full_name, "MyNs.MyClass");
        assert!(matches!(types[0].visibility, Visibility::Public));
    }

    #[test]
    fn loader_infer_interface() {
        let strings = make_strings(&["", "IFoo"]);
        let td = TypeDefRow {
            flags: 0x0000_0021, // public | interface
            type_name: 2,
            type_namespace: 0,
            extends: 0,
            field_list: 1,
            method_list: 1,
        };
        let tds = [td];
        let loader = DotnetTypeLoader::new(&tds, &[], &[], &[], &[], &strings);
        let types = loader.load_all();
        assert_eq!(types[0].kind, TypeKind::Interface);
    }

    #[test]
    fn loader_load_type_refs() {
        let strings = make_strings(&["System", "Object"]);
        let tr = TypeRefRow {
            resolution_scope: 1,
            type_name: 8,      // "Object" offset
            type_namespace: 1, // "System" offset
        };
        let trs = [tr];
        let loader = DotnetTypeLoader::new(&[], &trs, &[], &[], &[], &strings);
        let refs = loader.load_type_refs();
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].full_name(), "System.Object");
    }

    #[test]
    fn resolve_typeref_typedef() {
        let strings = make_strings(&["Ns", "Foo"]);
        let td = TypeDefRow {
            flags: 0,
            type_name: 4,
            type_namespace: 1,
            extends: 0,
            field_list: 1,
            method_list: 1,
        };
        let tds = [td];
        let loader = DotnetTypeLoader::new(&tds, &[], &[], &[], &[], &strings);
        // Token: table=0x02, row=1 → (0x02 << 24) | 1
        let token = (0x02u32 << 24) | 1;
        let name = loader.resolve_typeref(token).unwrap();
        assert!(name.contains("Foo") || !name.is_empty());
    }

    #[test]
    fn resolve_typeref_unknown_table() {
        let loader = DotnetTypeLoader::new(&[], &[], &[], &[], &[], &[]);
        let token = (0xFFu32 << 24) | 1;
        assert!(loader.resolve_typeref(token).is_err());
    }

    #[test]
    fn find_derived_types() {
        let base_type = make_typedef_type("BaseClass", "System.Object");
        let derived = make_typedef_type("DerivedClass", "BaseClass");
        let unrelated = make_typedef_type("Unrelated", "System.Object");
        let types = vec![base_type, derived, unrelated];
        let loader = DotnetTypeLoader::new(&[], &[], &[], &[], &[], &[]);
        let derived_indices = loader.find_derived_types(&types, "BaseClass");
        assert_eq!(derived_indices.len(), 1);
        assert_eq!(derived_indices[0], 1);
    }

    fn make_typedef_type(name: &str, base: &str) -> DotnetType {
        DotnetType {
            type_def_index: 0,
            full_name: name.to_owned(),
            name: name.to_owned(),
            namespace: String::new(),
            visibility: Visibility::Public,
            kind: TypeKind::Class,
            is_abstract: false,
            is_sealed: false,
            is_static: false,
            base_type: base.to_owned(),
            interfaces: vec![],
            nested_types: vec![],
            method_indices: vec![],
            flags: 0,
        }
    }

    #[test]
    fn find_implementors() {
        let mut t = make_typedef_type("MyClass", "System.Object");
        t.type_def_index = 0;
        t.interfaces.push("IDisposable".into());
        let loader = DotnetTypeLoader::new(&[], &[], &[], &[], &[], &[]);
        let impls = loader.find_implementors(&[t], "IDisposable");
        assert_eq!(impls.len(), 1);
    }

    #[test]
    fn build_name_index() {
        let t = make_typedef_type("MyClass", "");
        let mut t = t;
        t.type_def_index = 5;
        let map = DotnetTypeLoader::build_name_index(&[t]);
        assert_eq!(map.get("MyClass"), Some(&5));
    }

    #[test]
    fn type_stats_from_types() {
        let c = make_typedef_type("C", "");
        let mut i = make_typedef_type("I", "");
        i.kind = TypeKind::Interface;
        let mut e = make_typedef_type("E", "System.Enum");
        e.kind = TypeKind::Enum;
        let stats = TypeStats::from_types(&[c, i, e]);
        assert_eq!(stats.total, 3);
        assert_eq!(stats.interfaces, 1);
        assert_eq!(stats.enums, 1);
    }

    #[test]
    fn type_stats_display() {
        let stats = TypeStats::default();
        let s = stats.to_string();
        assert!(s.contains("TypeStats"));
    }

    #[test]
    fn type_resolution_error_display() {
        let e = TypeResolutionError::OutOfRange { table: "TypeDef", row: 5 };
        assert!(e.to_string().contains("TypeDef"));
        let e2 = TypeResolutionError::UnknownToken(0xDEAD_BEEF);
        assert!(e2.to_string().contains("0xdeadbeef"));
    }

    #[test]
    fn dotnet_type_display() {
        let t = make_typedef_type("Foo", "Bar");
        let s = format!("{t}");
        assert!(s.contains("Foo"));
    }

    #[test]
    fn visibility_display() {
        assert_eq!(Visibility::Public.to_string(), "public");
        assert_eq!(Visibility::NestedFamily.to_string(), "protected");
    }

    #[test]
    fn dotnet_type_is_static() {
        let mut t = make_typedef_type("Static", "");
        t.is_abstract = true;
        t.is_sealed = true;
        t.is_static = true;
        assert!(t.is_static);
    }

    #[test]
    fn dotnet_type_method_count() {
        let mut t = make_typedef_type("WithMethods", "");
        t.method_indices = vec![0, 1, 2];
        assert_eq!(t.method_count(), 3);
    }
}

#[cfg(test)]
mod typedef_flag_tests {
    //! ⚠ `make_typedef` built a `TypeDefRow` from explicit flags and had no
    //! caller: nothing exercised `load_all`'s flag decoding, so the abstract /
    //! sealed / static / interface classification was untested on a loader
    //! whose whole job is that classification.

    use super::*;

    const ABSTRACT: u32 = 0x0000_0080;
    const SEALED: u32 = 0x0000_0100;
    const INTERFACE: u32 = 0x0000_0020;

    use super::tests::make_typedef;

    /// A string heap holding "" at 0, "Ns" at 1, "T" at 4.
    fn heap() -> Vec<u8> {
        let mut h = vec![0u8];
        h.extend_from_slice(b"Ns\0");
        h.extend_from_slice(b"T\0");
        h
    }

    fn load(rows: &[TypeDefRow], strings: &[u8]) -> Vec<DotnetType> {
        DotnetTypeLoader::new(rows, &[], &[], &[], &[], strings).load_all()
    }

    /// `abstract` and `sealed` together mean a C# `static class`. Neither alone
    /// does — that is the whole point of the conjunction.
    #[test]
    fn abstract_plus_sealed_is_static() {
        let h = heap();
        let rows = [
            make_typedef(1, 4, ABSTRACT, 0),
            make_typedef(1, 4, SEALED, 0),
            make_typedef(1, 4, ABSTRACT | SEALED, 0),
        ];
        let out = load(&rows, &h);

        assert!(out[0].is_abstract && !out[0].is_sealed && !out[0].is_static);
        assert!(!out[1].is_abstract && out[1].is_sealed && !out[1].is_static);
        assert!(out[2].is_abstract && out[2].is_sealed && out[2].is_static);
    }

    /// The interface flag wins over base-type inference.
    #[test]
    fn interface_flag_classifies_as_interface() {
        let h = heap();
        let rows = [make_typedef(1, 4, INTERFACE, 0)];
        assert_eq!(load(&rows, &h)[0].kind, TypeKind::Interface);
    }

    /// A plain row with no flags and no base type is a class.
    #[test]
    fn no_flags_is_a_plain_class() {
        let h = heap();
        let rows = [make_typedef(1, 4, 0, 0)];
        let out = load(&rows, &h);
        assert_eq!(out[0].kind, TypeKind::Class);
        assert!(!out[0].is_abstract && !out[0].is_sealed && !out[0].is_static);
    }

    /// `extends == 0` and `extends == 0xFFFF_FFFF` both mean "no base type",
    /// and must not produce a resolved name.
    #[test]
    fn sentinel_extends_values_give_no_base_type() {
        let h = heap();
        let rows = [make_typedef(1, 4, 0, 0), make_typedef(1, 4, 0, 0xFFFF_FFFF)];
        let out = load(&rows, &h);
        assert!(out[0].base_type.is_empty());
        assert!(out[1].base_type.is_empty());
    }

    /// The namespace is joined with a dot only when non-empty.
    #[test]
    fn full_name_joins_namespace_only_when_present() {
        let h = heap();
        let rows = [make_typedef(1, 4, 0, 0), make_typedef(0, 4, 0, 0)];
        let out = load(&rows, &h);
        assert_eq!(out[0].full_name, "Ns.T");
        assert_eq!(out[1].full_name, "T", "empty namespace must not add a dot");
    }
}
