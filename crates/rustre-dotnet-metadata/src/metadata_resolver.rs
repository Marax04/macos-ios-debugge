//! .NET metadata resolver for `rustre-dotnet-metadata`.

use crate::{AssemblyRefRow, MemberRefRow, MetadataTables, MethodDefRow, TypeDefRow, TypeRefRow};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// Re-exports so resolver consumers can access related metadata row/reader types
// without reaching into the crate root.
pub use crate::{FieldRow, MetadataReader, TypeSpecRow};

// ── Resolution types ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolvedType {
    pub full_name: String,
    pub is_value_type: bool,
    pub source: TypeSource,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TypeSource {
    TypeDef { index: u32 },
    TypeRef { assembly: String },
    TypeSpec,
    Forwarded { to_assembly: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolvedMethod {
    pub declaring_type: String,
    pub name: String,
    pub signature: Vec<u8>,
    pub rva: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolvedMember {
    pub declaring_type: String,
    pub name: String,
    pub kind: MemberKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MemberKind {
    Method,
    Field,
    Property,
    Event,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PInvokeSignature {
    pub module_name: String,
    pub entry_point: String,
    pub calling_convention: String,
    pub charset: String,
}

// ── TypeResolver ──────────────────────────────────────────────────────────────

pub struct TypeResolver<'a> {
    tables: &'a MetadataTables,
}

impl<'a> TypeResolver<'a> {
    #[must_use]
    pub const fn new(tables: &'a MetadataTables) -> Self {
        Self { tables }
    }

    /// Resolve a `TypeRef` token to a `TypeDef` if the type is in the same assembly.
    #[must_use]
    pub fn resolve_type_ref(&self, type_ref: &TypeRefRow) -> Option<&TypeDefRow> {
        self.tables.type_def.iter().find(|td| {
            td.type_name == type_ref.type_name && td.type_namespace == type_ref.type_namespace
        })
    }

    /// Resolve a type name to its `TypeDef` index (1-based).
    #[must_use]
    pub fn find_type_def(&self, name: &str, namespace: &str) -> Option<u32> {
        self.tables.type_def.iter().enumerate().find_map(|(i, td)| {
            if td.type_name == name && td.type_namespace == namespace {
                Some(u32::try_from(i).unwrap_or(u32::MAX) + 1)
            } else {
                None
            }
        })
    }

    /// Get full name from a `TypeDef` row.
    #[must_use]
    pub fn full_name(td: &TypeDefRow) -> String {
        if td.type_namespace.is_empty() {
            td.type_name.clone()
        } else {
            format!("{}.{}", td.type_namespace, td.type_name)
        }
    }

    /// Resolve a TypeDef/TypeRef/TypeSpec coded token to a type name.
    #[must_use]
    pub fn resolve_coded_token(&self, coded: u32) -> Option<String> {
        let tag = coded & 0x3;
        let idx = (coded >> 2) as usize;
        match tag {
            0x0 => self
                .tables
                .type_def
                .get(idx.wrapping_sub(1))
                .map(Self::full_name),
            0x1 => self.tables.type_ref.get(idx.wrapping_sub(1)).map(|tr| {
                if tr.type_namespace.is_empty() {
                    tr.type_name.clone()
                } else {
                    format!("{}.{}", tr.type_namespace, tr.type_name)
                }
            }),
            0x2 => Some(format!("TypeSpec<{idx:x}>")),
            _ => None,
        }
    }

    /// List all types in the given namespace.
    #[must_use]
    pub fn types_in_namespace(&self, namespace: &str) -> Vec<&TypeDefRow> {
        self.tables
            .type_def
            .iter()
            .filter(|td| td.type_namespace == namespace)
            .collect()
    }
}

// ── MemberResolver ────────────────────────────────────────────────────────────

pub struct MemberResolver<'a> {
    tables: &'a MetadataTables,
}

impl<'a> MemberResolver<'a> {
    #[must_use]
    pub const fn new(tables: &'a MetadataTables) -> Self {
        Self { tables }
    }

    /// Resolve a `MemberRef` to a (`type_name`, `member_name`) pair.
    #[must_use]
    pub fn resolve_member_ref(&self, mr: &MemberRefRow) -> Option<ResolvedMember> {
        let type_resolver = TypeResolver::new(self.tables);
        let declaring_type = type_resolver.resolve_coded_token(mr.class)?;
        Some(ResolvedMember {
            declaring_type,
            name: mr.name.clone(),
            kind: MemberKind::Method,
        })
    }

    /// Resolve all `MemberRefs` by name.
    #[must_use]
    pub fn find_by_name(&self, name: &str) -> Vec<&MemberRefRow> {
        self.tables
            .member_ref
            .iter()
            .filter(|mr| mr.name == name)
            .collect()
    }
}

// ── MethodResolver ────────────────────────────────────────────────────────────

pub struct MethodResolver<'a> {
    tables: &'a MetadataTables,
}

impl<'a> MethodResolver<'a> {
    #[must_use]
    pub const fn new(tables: &'a MetadataTables) -> Self {
        Self { tables }
    }

    /// Find a method by type and method name.
    #[must_use]
    pub fn find_method(&self, type_name: &str, method_name: &str) -> Option<(u32, &MethodDefRow)> {
        let td = self.tables.type_def.iter().enumerate().find(|(_, td)| {
            td.type_name == type_name
                || format!("{}.{}", td.type_namespace, td.type_name) == type_name
        });
        let (td_idx, td) = td?;
        let method_end = self.tables.type_def.get(td_idx + 1).map_or_else(
            || u32::try_from(self.tables.method_def.len()).unwrap_or(u32::MAX) + 1,
            |r| r.method_list,
        );
        for mi in td.method_list..method_end {
            let idx = mi as usize - 1;
            if let Some(m) = self.tables.method_def.get(idx)
                && m.name == method_name
            {
                return Some((mi, m));
            }
        }
        None
    }

    /// Resolve a method token (0x06XXXXXX) to its row.
    #[must_use]
    pub fn resolve_method_token(&self, token: u32) -> Option<&MethodDefRow> {
        let idx = (token & 0x00FF_FFFF) as usize;
        if idx == 0 {
            return None;
        }
        self.tables.method_def.get(idx - 1)
    }

    /// List all methods with a given name across all types.
    #[must_use]
    pub fn find_all_by_name(&self, name: &str) -> Vec<(String, &MethodDefRow)> {
        let mut results = Vec::new();
        for (ti, td) in self.tables.type_def.iter().enumerate() {
            let method_end = self.tables.type_def.get(ti + 1).map_or_else(
                || u32::try_from(self.tables.method_def.len()).unwrap_or(u32::MAX) + 1,
                |r| r.method_list,
            );
            for mi in td.method_list..method_end {
                if let Some(m) = self.tables.method_def.get((mi as usize).wrapping_sub(1))
                    && m.name == name
                {
                    let type_name = if td.type_namespace.is_empty() {
                        td.type_name.clone()
                    } else {
                        format!("{}.{}", td.type_namespace, td.type_name)
                    };
                    results.push((type_name, m));
                }
            }
        }
        results
    }
}

// ── AssemblyResolver ──────────────────────────────────────────────────────────

pub struct AssemblyResolver<'a> {
    tables: &'a MetadataTables,
    search_paths: Vec<String>,
}

impl<'a> AssemblyResolver<'a> {
    #[must_use]
    pub const fn new(tables: &'a MetadataTables) -> Self {
        Self {
            tables,
            search_paths: Vec::new(),
        }
    }

    pub fn add_search_path(&mut self, path: impl Into<String>) {
        self.search_paths.push(path.into());
    }

    #[must_use]
    pub fn find_assembly_ref(&self, name: &str) -> Option<&AssemblyRefRow> {
        self.tables.assembly_ref.iter().find(|ar| ar.name == name)
    }

    #[must_use]
    pub fn all_referenced_assemblies(&self) -> Vec<String> {
        self.tables
            .assembly_ref
            .iter()
            .map(|ar| ar.name.clone())
            .collect()
    }

    #[must_use]
    pub fn is_known_assembly(&self, name: &str) -> bool {
        const KNOWN: &[&str] = &[
            "mscorlib",
            "System",
            "System.Core",
            "System.Runtime",
            "netstandard",
            "System.Collections",
            "System.Linq",
        ];
        KNOWN.contains(&name)
    }
}

// ── ForwardedType ─────────────────────────────────────────────────────────────

/// A type forwarded to another assembly.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForwardedType {
    pub type_name: String,
    pub type_namespace: String,
    pub target_assembly: String,
}

pub struct ForwardedTypeResolver<'a> {
    tables: &'a MetadataTables,
}

impl<'a> ForwardedTypeResolver<'a> {
    #[must_use]
    pub const fn new(tables: &'a MetadataTables) -> Self {
        Self { tables }
    }

    #[must_use]
    pub fn find_all_forwarded(&self) -> Vec<ForwardedType> {
        self.tables
            .exported_type
            .iter()
            .filter_map(|et| {
                let assembly_idx = (et.implementation >> 2) as usize;
                let target = self
                    .tables
                    .assembly_ref
                    .get(assembly_idx.wrapping_sub(1))?
                    .name
                    .clone();
                Some(ForwardedType {
                    type_name: et.type_name.clone(),
                    type_namespace: et.type_namespace.clone(),
                    target_assembly: target,
                })
            })
            .collect()
    }
}

// ── NativeInterop ─────────────────────────────────────────────────────────────

pub struct NativeInteropResolver<'a> {
    tables: &'a MetadataTables,
}

impl<'a> NativeInteropResolver<'a> {
    #[must_use]
    pub const fn new(tables: &'a MetadataTables) -> Self {
        Self { tables }
    }

    #[must_use]
    pub fn find_pinvoke_methods(&self) -> Vec<(String, PInvokeSignature)> {
        let mut results = Vec::with_capacity(self.tables.impl_map.len());
        for im in &self.tables.impl_map {
            let member_idx = (im.member_forwarded >> 1) as usize;
            let method_name = self
                .tables
                .method_def
                .get(member_idx.wrapping_sub(1))
                .map(|m| m.name.clone())
                .unwrap_or_default();
            let module_name = self
                .tables
                .module_ref
                .get(im.import_scope as usize - 1)
                .map(|mr| mr.name.clone())
                .unwrap_or_default();
            results.push((
                method_name,
                PInvokeSignature {
                    module_name,
                    entry_point: im.import_name.clone(),
                    calling_convention: Self::calling_conv_name(im.mapping_flags).to_string(),
                    charset: Self::charset_name(im.mapping_flags).to_string(),
                },
            ));
        }
        results
    }

    fn calling_conv_name(flags: u16) -> &'static str {
        match flags & 0x0700 {
            0x0100 => "winapi",
            0x0200 => "cdecl",
            0x0300 => "stdcall",
            0x0400 => "thiscall",
            0x0500 => "fastcall",
            _ => "default",
        }
    }

    fn charset_name(flags: u16) -> &'static str {
        match flags & 0x0006 {
            0x0002 => "ansi",
            0x0004 => "unicode",
            0x0006 => "auto",
            _ => "none",
        }
    }
}

// ── MetadataResolver ─────────────────────────────────────────────────────────

pub struct MetadataResolver<'a> {
    pub tables: &'a MetadataTables,
    type_cache: HashMap<String, u32>,
}

impl<'a> MetadataResolver<'a> {
    #[must_use]
    pub fn new(tables: &'a MetadataTables) -> Self {
        let mut cache = HashMap::with_capacity(tables.type_def.len());
        for (i, td) in tables.type_def.iter().enumerate() {
            let full = if td.type_namespace.is_empty() {
                td.type_name.clone()
            } else {
                format!("{}.{}", td.type_namespace, td.type_name)
            };
            cache.insert(full, u32::try_from(i).unwrap_or(u32::MAX) + 1);
        }
        Self {
            tables,
            type_cache: cache,
        }
    }

    #[must_use]
    pub const fn type_resolver(&self) -> TypeResolver<'_> {
        TypeResolver::new(self.tables)
    }
    #[must_use]
    pub const fn member_resolver(&self) -> MemberResolver<'_> {
        MemberResolver::new(self.tables)
    }
    #[must_use]
    pub const fn method_resolver(&self) -> MethodResolver<'_> {
        MethodResolver::new(self.tables)
    }
    #[must_use]
    pub const fn assembly_resolver(&self) -> AssemblyResolver<'_> {
        AssemblyResolver::new(self.tables)
    }
    #[must_use]
    pub const fn forwarded_type_resolver(&self) -> ForwardedTypeResolver<'_> {
        ForwardedTypeResolver::new(self.tables)
    }
    #[must_use]
    pub const fn native_interop_resolver(&self) -> NativeInteropResolver<'_> {
        NativeInteropResolver::new(self.tables)
    }

    #[must_use]
    pub fn is_type_cached(&self, full_name: &str) -> bool {
        self.type_cache.contains_key(full_name)
    }

    #[must_use]
    pub const fn type_count(&self) -> usize {
        self.tables.type_def.len()
    }

    #[must_use]
    pub const fn method_count(&self) -> usize {
        self.tables.method_def.len()
    }

    #[must_use]
    pub const fn assembly_ref_count(&self) -> usize {
        self.tables.assembly_ref.len()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_tables() -> MetadataTables {
        MetadataTables::default()
    }

    fn tables_with_type(name: &str, ns: &str) -> MetadataTables {
        let mut t = MetadataTables::default();
        t.type_def.push(TypeDefRow {
            flags: 0x01,
            type_name: name.to_string(),
            type_namespace: ns.to_string(),
            extends: 0,
            field_list: 1,
            method_list: 1,
        });
        t
    }

    fn tables_with_method(type_name: &str, method_name: &str) -> MetadataTables {
        let mut t = tables_with_type(type_name, "Test");
        t.method_def.push(MethodDefRow {
            rva: 0,
            impl_flags: 0,
            flags: 0,
            name: method_name.to_string(),
            signature: vec![],
            param_list: 1,
        });
        t
    }

    // ── TypeResolver ─────────────────────────────────────────────────────────

    #[test]
    fn test_type_resolver_find_typedef() {
        let tables = tables_with_type("MyClass", "MyNs");
        let r = TypeResolver::new(&tables);
        assert!(r.find_type_def("MyClass", "MyNs").is_some());
        assert!(r.find_type_def("Missing", "MyNs").is_none());
    }

    #[test]
    fn test_type_resolver_full_name() {
        let td = TypeDefRow {
            type_name: "Foo".into(),
            type_namespace: "Bar".into(),
            ..Default::default()
        };
        assert_eq!(TypeResolver::full_name(&td), "Bar.Foo");
    }

    #[test]
    fn test_type_resolver_full_name_no_ns() {
        let td = TypeDefRow {
            type_name: "Foo".into(),
            type_namespace: String::new(),
            ..Default::default()
        };
        assert_eq!(TypeResolver::full_name(&td), "Foo");
    }

    #[test]
    fn test_type_resolver_resolve_type_ref() {
        let mut tables = tables_with_type("MyClass", "MyNs");
        tables.type_ref.push(TypeRefRow {
            resolution_scope: 0,
            type_name: "MyClass".into(),
            type_namespace: "MyNs".into(),
        });
        let r = TypeResolver::new(&tables);
        let tr = &tables.type_ref[0];
        assert!(r.resolve_type_ref(tr).is_some());
    }

    #[test]
    fn test_type_resolver_types_in_namespace() {
        let tables = tables_with_type("A", "Ns");
        let r = TypeResolver::new(&tables);
        let types = r.types_in_namespace("Ns");
        assert_eq!(types.len(), 1);
        assert!(r.types_in_namespace("Other").is_empty());
    }

    #[test]
    fn test_type_resolver_coded_token_typedef() {
        let tables = tables_with_type("T", "N");
        let r = TypeResolver::new(&tables);
        // TypeDef coded token: (1 << 2) | 0x0 = 4
        let name = r.resolve_coded_token(4);
        assert!(name.is_some());
    }

    // ── MemberResolver ────────────────────────────────────────────────────────

    #[test]
    fn test_member_resolver_find_by_name() {
        let mut tables = empty_tables();
        tables.member_ref.push(MemberRefRow {
            class: 0,
            name: "ToString".into(),
            signature: vec![],
        });
        let r = MemberResolver::new(&tables);
        let found = r.find_by_name("ToString");
        assert_eq!(found.len(), 1);
    }

    #[test]
    fn test_member_resolver_not_found() {
        let tables = empty_tables();
        let r = MemberResolver::new(&tables);
        assert!(r.find_by_name("Missing").is_empty());
    }

    // ── MethodResolver ────────────────────────────────────────────────────────

    #[test]
    fn test_method_resolver_find_method() {
        let tables = tables_with_method("MyClass", "DoWork");
        let r = MethodResolver::new(&tables);
        let result = r.find_method("MyClass", "DoWork");
        assert!(result.is_some());
    }

    #[test]
    fn test_method_resolver_not_found() {
        let tables = tables_with_method("A", "B");
        let r = MethodResolver::new(&tables);
        assert!(r.find_method("A", "Missing").is_none());
    }

    #[test]
    fn test_method_resolver_find_all_by_name() {
        let mut tables = tables_with_method("A", "Initialize");
        let tables2 = tables_with_method("B", "Initialize");
        tables.type_def.extend(tables2.type_def);
        tables.method_def.extend(tables2.method_def);
        let r = MethodResolver::new(&tables);
        let all = r.find_all_by_name("Initialize");
        assert!(!all.is_empty());
    }

    #[test]
    fn test_method_resolver_token() {
        let tables = tables_with_method("T", "M");
        let r = MethodResolver::new(&tables);
        let m = r.resolve_method_token(0x0600_0001);
        assert!(m.is_some());
    }

    // ── AssemblyResolver ──────────────────────────────────────────────────────

    #[test]
    fn test_assembly_resolver_known_assemblies() {
        let tables = empty_tables();
        let r = AssemblyResolver::new(&tables);
        assert!(r.is_known_assembly("mscorlib"));
        assert!(r.is_known_assembly("System"));
        assert!(!r.is_known_assembly("malware.core"));
    }

    #[test]
    fn test_assembly_resolver_find_ref() {
        let mut tables = empty_tables();
        tables.assembly_ref.push(crate::AssemblyRefRow {
            name: "mscorlib".into(),
            ..Default::default()
        });
        let r = AssemblyResolver::new(&tables);
        assert!(r.find_assembly_ref("mscorlib").is_some());
        assert!(r.find_assembly_ref("missing").is_none());
    }

    #[test]
    fn test_assembly_resolver_all_refs() {
        let mut tables = empty_tables();
        tables.assembly_ref.push(crate::AssemblyRefRow {
            name: "A".into(),
            ..Default::default()
        });
        tables.assembly_ref.push(crate::AssemblyRefRow {
            name: "B".into(),
            ..Default::default()
        });
        let r = AssemblyResolver::new(&tables);
        let all = r.all_referenced_assemblies();
        assert_eq!(all.len(), 2);
    }

    // ── MetadataResolver ─────────────────────────────────────────────────────

    #[test]
    fn test_metadata_resolver_creation() {
        let tables = tables_with_type("Foo", "Bar");
        let r = MetadataResolver::new(&tables);
        assert_eq!(r.type_count(), 1);
    }

    #[test]
    fn test_metadata_resolver_cache() {
        let tables = tables_with_type("Baz", "Qux");
        let r = MetadataResolver::new(&tables);
        assert!(r.is_type_cached("Qux.Baz"));
        assert!(!r.is_type_cached("Missing"));
    }

    #[test]
    fn test_metadata_resolver_method_count() {
        let tables = tables_with_method("T", "M");
        let r = MetadataResolver::new(&tables);
        assert_eq!(r.method_count(), 1);
    }

    #[test]
    fn test_metadata_resolver_assembly_ref_count() {
        let mut tables = empty_tables();
        tables.assembly_ref.push(crate::AssemblyRefRow {
            name: "mscorlib".into(),
            ..Default::default()
        });
        let r = MetadataResolver::new(&tables);
        assert_eq!(r.assembly_ref_count(), 1);
    }

    #[test]
    fn test_forwarded_type_resolver_empty() {
        let tables = empty_tables();
        let r = ForwardedTypeResolver::new(&tables);
        assert!(r.find_all_forwarded().is_empty());
    }

    #[test]
    fn test_native_interop_resolver_empty() {
        let tables = empty_tables();
        let r = NativeInteropResolver::new(&tables);
        assert!(r.find_pinvoke_methods().is_empty());
    }
}
