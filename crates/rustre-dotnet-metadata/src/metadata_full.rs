//! `metadata_full` — high-level .NET metadata analysis layer.
//!
//! Provides [`MetadataFull`] as a rich analysis engine over
//! [`MetadataReader`](crate::MetadataReader), plus typed wrappers and
//! analysis helpers for the common ECMA-335 tables.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::MetadataReader;

// Re-export the underlying ECMA-335 row types and table container at this
// module path so consumers of `metadata_full` can access the raw rows behind
// the rich wrappers without reaching back into the crate root. `HashMap` is
// also re-exported because several of the analysis helpers below return
// collections keyed by metadata indices and downstream code commonly needs
// the matching map type in scope.
pub use crate::{
    AssemblyRefRow, AssemblyRow, CustomAttributeRow, DeclSecurityRow, FieldRow, MemberRefRow,
    MetadataTables, MethodDefRow, MethodSpecRow, ModuleRefRow, TypeDefRow, TypeRefRow, TypeSpecRow,
};
pub use std::collections::HashMap;

// ─── TypeDef ─────────────────────────────────────────────────────────────────

/// Enriched view of a `TypeDef` table row.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TypeDef {
    /// 1-based index in the `TypeDef` table.
    pub index: u32,
    /// Namespace of the type (may be empty).
    pub namespace: String,
    /// Simple name of the type.
    pub name: String,
    /// Combined flags word from the table row.
    pub flags: u32,
    /// 1-based range of methods belonging to this type.
    pub method_range: (u32, u32),
    /// 1-based range of fields belonging to this type.
    pub field_range: (u32, u32),
    /// Fully qualified name (`Namespace.Name`).
    pub full_name: String,
}

impl TypeDef {
    /// Returns `true` if the type is publicly visible at the top level.
    #[must_use]
    pub const fn is_public(&self) -> bool {
        self.flags & 0x7 == 0x01
    }

    /// Returns `true` if the type is abstract.
    #[must_use]
    pub const fn is_abstract(&self) -> bool {
        self.flags & 0x0080 != 0
    }

    /// Returns `true` if the type is sealed.
    #[must_use]
    pub const fn is_sealed(&self) -> bool {
        self.flags & 0x0100 != 0
    }

    /// Returns `true` if the type is an interface.
    #[must_use]
    pub const fn is_interface(&self) -> bool {
        self.flags & 0x0020 != 0
    }

    /// Returns `true` if the type is an enum.
    #[must_use]
    pub const fn is_enum(&self) -> bool {
        self.flags & 0x8 == 0 && self.flags & 0x10 != 0 // simplified heuristic
    }

    /// Number of methods in this type.
    #[must_use]
    pub const fn method_count(&self) -> u32 {
        self.method_range.1.saturating_sub(self.method_range.0)
    }

    /// Number of fields in this type.
    #[must_use]
    pub const fn field_count(&self) -> u32 {
        self.field_range.1.saturating_sub(self.field_range.0)
    }
}

// ─── MethodDef ───────────────────────────────────────────────────────────────

/// Enriched view of a `MethodDef` table row.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MethodDef {
    /// 1-based index in the `MethodDef` table.
    pub index: u32,
    /// Declaring type 1-based index.
    pub declaring_type: u32,
    /// Method name.
    pub name: String,
    /// Method attributes (flags).
    pub flags: u16,
    /// Implementation flags.
    pub impl_flags: u16,
    /// RVA of the method body (0 = abstract or extern).
    pub rva: u32,
    /// Raw signature blob.
    pub signature: Vec<u8>,
    /// 1-based parameter list start.
    pub param_list: u32,
}

impl MethodDef {
    /// Returns `true` if this is a public method.
    #[must_use]
    pub const fn is_public(&self) -> bool {
        self.flags & 0x0006 == 0x0006
    }

    /// Returns `true` if this is a static method.
    #[must_use]
    pub const fn is_static(&self) -> bool {
        self.flags & 0x0010 != 0
    }

    /// Returns `true` if this method has a body (non-abstract, non-extern).
    #[must_use]
    pub const fn has_body(&self) -> bool {
        self.rva != 0
    }

    /// Returns `true` if this method is abstract.
    #[must_use]
    pub const fn is_abstract(&self) -> bool {
        self.flags & 0x0400 != 0
    }

    /// Returns `true` if this method is virtual.
    #[must_use]
    pub const fn is_virtual(&self) -> bool {
        self.flags & 0x0040 != 0
    }

    /// Returns `true` if this is a constructor.
    #[must_use]
    pub fn is_constructor(&self) -> bool {
        self.name == ".ctor" || self.name == ".cctor"
    }
}

// ─── FieldDef ────────────────────────────────────────────────────────────────

/// Enriched view of a `Field` table row.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldDef {
    /// 1-based index in the Field table.
    pub index: u32,
    /// Declaring type 1-based index.
    pub declaring_type: u32,
    /// Field name.
    pub name: String,
    /// Field attribute flags.
    pub flags: u16,
    /// Raw field signature blob.
    pub signature: Vec<u8>,
}

impl FieldDef {
    /// Returns `true` if the field is public.
    #[must_use]
    pub const fn is_public(&self) -> bool {
        self.flags & 0x07 == 0x06
    }

    /// Returns `true` if the field is static.
    #[must_use]
    pub const fn is_static(&self) -> bool {
        self.flags & 0x0010 != 0
    }

    /// Returns `true` if the field is `initonly` (readonly).
    #[must_use]
    pub const fn is_readonly(&self) -> bool {
        self.flags & 0x0020 != 0
    }

    /// Returns `true` if the field is a compile-time literal constant.
    #[must_use]
    pub const fn is_literal(&self) -> bool {
        self.flags & 0x0040 != 0
    }
}

// ─── MemberRef ───────────────────────────────────────────────────────────────

/// A reference to a method or field in another type or assembly.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemberRef {
    /// 1-based index in the `MemberRef` table.
    pub index: u32,
    /// Name of the referenced member.
    pub name: String,
    /// Coded parent class index.
    pub class: u32,
    /// Raw signature blob.
    pub signature: Vec<u8>,
}

// ─── CustomAttribute ─────────────────────────────────────────────────────────

/// A custom attribute applied to a metadata entity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomAttribute {
    /// 1-based index in the `CustomAttribute` table.
    pub index: u32,
    /// Coded parent.
    pub parent: u32,
    /// Coded attribute type (constructor).
    pub attr_type: u32,
    /// Raw value blob.
    pub value: Vec<u8>,
}

// ─── DeclSecurity ────────────────────────────────────────────────────────────

/// A declarative security entry (`.demand`, `.permset`…).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeclSecurity {
    /// 1-based index in the `DeclSecurity` table.
    pub index: u32,
    /// Security action code.
    pub action: u16,
    /// Coded parent.
    pub parent: u32,
    /// Raw permission set blob.
    pub permission_set: Vec<u8>,
}

impl DeclSecurity {
    /// Returns `true` if the action represents a `Demand`.
    #[must_use]
    pub const fn is_demand(&self) -> bool {
        self.action == 2 // CorDeclSecurity.Demand
    }

    /// Returns `true` if the permission set is non-trivial.
    #[must_use]
    pub const fn has_permissions(&self) -> bool {
        !self.permission_set.is_empty()
    }
}

// ─── TypeSpec ────────────────────────────────────────────────────────────────

/// An instantiated or constructed generic type specification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TypeSpec {
    /// 1-based index in the `TypeSpec` table.
    pub index: u32,
    /// Raw signature blob encoding the type.
    pub signature: Vec<u8>,
}

impl TypeSpec {
    /// Returns `true` if this looks like a generic instantiation (GENERICINST prefix).
    #[must_use]
    pub fn is_generic_instantiation(&self) -> bool {
        self.signature.first().copied() == Some(0x15) // ELEMENT_TYPE_GENERICINST
    }
}

// ─── MethodSpec ──────────────────────────────────────────────────────────────

/// A generic method instantiation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MethodSpec {
    /// 1-based index in the `MethodSpec` table.
    pub index: u32,
    /// Coded `MethodDefOrRef`.
    pub method: u32,
    /// Raw instantiation blob.
    pub instantiation: Vec<u8>,
}

// ─── AssemblyInfo ─────────────────────────────────────────────────────────────

/// High-level assembly identity and version information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssemblyInfo {
    /// Assembly name.
    pub name: String,
    /// Culture string (empty for neutral).
    pub culture: String,
    /// Version tuple: `(major, minor, build, revision)`.
    pub version: (u16, u16, u16, u16),
    /// Whether the assembly has a strong name.
    pub has_strong_name: bool,
    /// Hash algorithm ID.
    pub hash_alg_id: u32,
}

impl AssemblyInfo {
    /// Version string in `major.minor.build.revision` format.
    #[must_use]
    pub fn version_string(&self) -> String {
        let (ma, mi, b, r) = self.version;
        format!("{ma}.{mi}.{b}.{r}")
    }

    /// Returns `true` if culture is neutral (empty).
    #[must_use]
    pub const fn is_neutral_culture(&self) -> bool {
        self.culture.is_empty()
    }
}

// ─── AssemblyRefInfo ──────────────────────────────────────────────────────────

/// Reference to an external assembly.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssemblyRefInfo {
    /// 1-based index.
    pub index: u32,
    /// Assembly name.
    pub name: String,
    /// Culture string.
    pub culture: String,
    /// Version tuple.
    pub version: (u16, u16, u16, u16),
    /// Whether a public key token is present.
    pub has_public_key_token: bool,
}

impl AssemblyRefInfo {
    /// Version string.
    #[must_use]
    pub fn version_string(&self) -> String {
        let (ma, mi, b, r) = self.version;
        format!("{ma}.{mi}.{b}.{r}")
    }
}

// ─── MetadataStats ────────────────────────────────────────────────────────────

/// Aggregated statistics over all metadata tables.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetadataStats {
    /// Number of `TypeDef` rows.
    pub type_def_count: usize,
    /// Number of `MethodDef` rows.
    pub method_def_count: usize,
    /// Number of Field rows.
    pub field_count: usize,
    /// Number of `TypeRef` rows.
    pub type_ref_count: usize,
    /// Number of `MemberRef` rows.
    pub member_ref_count: usize,
    /// Number of `CustomAttribute` rows.
    pub custom_attribute_count: usize,
    /// Number of `AssemblyRef` rows.
    pub assembly_ref_count: usize,
    /// Number of `GenericParam` rows.
    pub generic_param_count: usize,
    /// Number of `MethodSpec` rows.
    pub method_spec_count: usize,
    /// Number of `TypeSpec` rows.
    pub type_spec_count: usize,
    /// Number of `DeclSecurity` rows.
    pub decl_security_count: usize,
}

// ─── MetadataFull ─────────────────────────────────────────────────────────────

/// High-level analysis engine over a parsed `.NET` metadata blob.
pub struct MetadataFull<'a> {
    reader: &'a MetadataReader,
}

impl<'a> MetadataFull<'a> {
    /// Wrap a [`MetadataReader`].
    #[must_use]
    pub const fn new(reader: &'a MetadataReader) -> Self {
        Self { reader }
    }

    // ── TypeDef helpers ───────────────────────────────────────────────────────

    /// Iterate all `TypeDef` rows as enriched [`TypeDef`] values.
    #[must_use]
    pub fn type_defs(&self) -> Vec<TypeDef> {
        let table = &self.reader.tables;
        let count = table.type_def.len();
        (0..count)
            .map(|i| {
                let row = &table.type_def[i];
                let next = table.type_def.get(i + 1);
                let method_end = next.map_or_else(
                    || u32::try_from(table.method_def.len()).unwrap_or(u32::MAX) + 1,
                    |r| r.method_list,
                );
                let field_end = next.map_or_else(
                    || u32::try_from(table.field.len()).unwrap_or(u32::MAX) + 1,
                    |r| r.field_list,
                );
                let full_name = if row.type_namespace.is_empty() {
                    row.type_name.clone()
                } else {
                    format!("{}.{}", row.type_namespace, row.type_name)
                };
                TypeDef {
                    index: u32::try_from(i).unwrap_or(u32::MAX) + 1,
                    namespace: row.type_namespace.clone(),
                    name: row.type_name.clone(),
                    flags: row.flags,
                    method_range: (row.method_list, method_end),
                    field_range: (row.field_list, field_end),
                    full_name,
                }
            })
            .collect()
    }

    /// Find a `TypeDef` by full name (or simple name).
    #[must_use]
    pub fn find_type(&self, name: &str) -> Option<TypeDef> {
        self.type_defs()
            .into_iter()
            .find(|t| t.full_name == name || t.name == name)
    }

    // ── MethodDef helpers ─────────────────────────────────────────────────────

    /// Return all `MethodDef` rows for a given type (by 1-based type index).
    #[must_use]
    pub fn methods_of_type(&self, type_idx: u32) -> Vec<MethodDef> {
        let table = &self.reader.tables;
        let type_defs = &table.type_def;
        let i = (type_idx as usize).saturating_sub(1);
        if i >= type_defs.len() {
            return vec![];
        }

        let row = &type_defs[i];
        let next = type_defs.get(i + 1);
        let method_end = next.map_or_else(
            || u32::try_from(table.method_def.len()).unwrap_or(u32::MAX) + 1,
            |r| r.method_list,
        );

        (row.method_list..method_end)
            .filter_map(|mi| {
                let mi_idx = (mi as usize).saturating_sub(1);
                table.method_def.get(mi_idx).map(|m| MethodDef {
                    index: mi,
                    declaring_type: type_idx,
                    name: m.name.clone(),
                    flags: m.flags,
                    impl_flags: m.impl_flags,
                    rva: m.rva,
                    signature: m.signature.clone(),
                    param_list: m.param_list,
                })
            })
            .collect()
    }

    /// Return all `MethodDef` rows across the entire assembly.
    #[must_use]
    pub fn all_methods(&self) -> Vec<MethodDef> {
        let table = &self.reader.tables;
        let type_count = table.type_def.len();
        (1..=u32::try_from(type_count).unwrap_or(u32::MAX))
            .flat_map(|ti| self.methods_of_type(ti))
            .collect()
    }

    // ── FieldDef helpers ──────────────────────────────────────────────────────

    /// Return all `FieldDef` rows for a given type.
    #[must_use]
    pub fn fields_of_type(&self, type_idx: u32) -> Vec<FieldDef> {
        let table = &self.reader.tables;
        let i = (type_idx as usize).saturating_sub(1);
        if i >= table.type_def.len() {
            return vec![];
        }
        let row = &table.type_def[i];
        let next = table.type_def.get(i + 1);
        let field_end = next.map_or_else(
            || u32::try_from(table.field.len()).unwrap_or(u32::MAX) + 1,
            |r| r.field_list,
        );

        (row.field_list..field_end)
            .filter_map(|fi| {
                let fi_idx = (fi as usize).saturating_sub(1);
                table.field.get(fi_idx).map(|f| FieldDef {
                    index: fi,
                    declaring_type: type_idx,
                    name: f.name.clone(),
                    flags: f.flags,
                    signature: f.signature.clone(),
                })
            })
            .collect()
    }

    // ── MemberRef helpers ─────────────────────────────────────────────────────

    /// Return all `MemberRef` rows.
    #[must_use]
    pub fn member_refs(&self) -> Vec<MemberRef> {
        self.reader
            .tables
            .member_ref
            .iter()
            .enumerate()
            .map(|(i, r)| MemberRef {
                index: u32::try_from(i).unwrap_or(u32::MAX) + 1,
                name: r.name.clone(),
                class: r.class,
                signature: r.signature.clone(),
            })
            .collect()
    }

    /// Find `MemberRef` rows by name substring.
    #[must_use]
    pub fn find_member_refs(&self, name: &str) -> Vec<MemberRef> {
        self.member_refs()
            .into_iter()
            .filter(|r| r.name.contains(name))
            .collect()
    }

    // ── CustomAttribute helpers ───────────────────────────────────────────────

    /// Return all `CustomAttribute` rows.
    #[must_use]
    pub fn custom_attributes(&self) -> Vec<CustomAttribute> {
        self.reader
            .tables
            .custom_attribute
            .iter()
            .enumerate()
            .map(|(i, r)| CustomAttribute {
                index: u32::try_from(i).unwrap_or(u32::MAX) + 1,
                parent: r.parent,
                attr_type: r.attr_type,
                value: r.value.clone(),
            })
            .collect()
    }

    // ── DeclSecurity helpers ──────────────────────────────────────────────────

    /// Return all `DeclSecurity` rows.
    #[must_use]
    pub fn decl_security_entries(&self) -> Vec<DeclSecurity> {
        self.reader
            .tables
            .decl_security
            .iter()
            .enumerate()
            .map(|(i, r)| DeclSecurity {
                index: u32::try_from(i).unwrap_or(u32::MAX) + 1,
                action: r.action,
                parent: r.parent,
                permission_set: r.permission_set.clone(),
            })
            .collect()
    }

    // ── TypeSpec helpers ──────────────────────────────────────────────────────

    /// Return all `TypeSpec` rows.
    #[must_use]
    pub fn type_specs(&self) -> Vec<TypeSpec> {
        self.reader
            .tables
            .type_spec
            .iter()
            .enumerate()
            .map(|(i, r)| TypeSpec {
                index: u32::try_from(i).unwrap_or(u32::MAX) + 1,
                signature: r.signature.clone(),
            })
            .collect()
    }

    // ── MethodSpec helpers ────────────────────────────────────────────────────

    /// Return all `MethodSpec` rows.
    #[must_use]
    pub fn method_specs(&self) -> Vec<MethodSpec> {
        self.reader
            .tables
            .method_spec
            .iter()
            .enumerate()
            .map(|(i, r)| MethodSpec {
                index: u32::try_from(i).unwrap_or(u32::MAX) + 1,
                method: r.method,
                instantiation: r.instantiation.clone(),
            })
            .collect()
    }

    // ── Assembly / AssemblyRef helpers ────────────────────────────────────────

    /// Return the primary assembly information.
    #[must_use]
    pub fn assembly_info(&self) -> Option<AssemblyInfo> {
        self.reader.tables.assembly.first().map(|a| AssemblyInfo {
            name: a.name.clone(),
            culture: a.culture.clone(),
            version: (
                a.major_version,
                a.minor_version,
                a.build_number,
                a.revision_number,
            ),
            has_strong_name: !a.public_key.is_empty(),
            hash_alg_id: a.hash_alg_id,
        })
    }

    /// Return all referenced assemblies.
    #[must_use]
    pub fn assembly_refs(&self) -> Vec<AssemblyRefInfo> {
        self.reader
            .tables
            .assembly_ref
            .iter()
            .enumerate()
            .map(|(i, r)| AssemblyRefInfo {
                index: u32::try_from(i).unwrap_or(u32::MAX) + 1,
                name: r.name.clone(),
                culture: r.culture.clone(),
                version: (
                    r.major_version,
                    r.minor_version,
                    r.build_number,
                    r.revision_number,
                ),
                has_public_key_token: !r.public_key_or_token.is_empty(),
            })
            .collect()
    }

    // ── Statistics ────────────────────────────────────────────────────────────

    /// Compute aggregate table statistics.
    #[must_use]
    pub const fn stats(&self) -> MetadataStats {
        let t = &self.reader.tables;
        MetadataStats {
            type_def_count: t.type_def.len(),
            method_def_count: t.method_def.len(),
            field_count: t.field.len(),
            type_ref_count: t.type_ref.len(),
            member_ref_count: t.member_ref.len(),
            custom_attribute_count: t.custom_attribute.len(),
            assembly_ref_count: t.assembly_ref.len(),
            generic_param_count: t.generic_param.len(),
            method_spec_count: t.method_spec.len(),
            type_spec_count: t.type_spec.len(),
            decl_security_count: t.decl_security.len(),
        }
    }

    // ── Analysis helpers ──────────────────────────────────────────────────────

    /// Collect all unique namespaces declared in the assembly.
    #[must_use]
    pub fn namespaces(&self) -> Vec<String> {
        let mut ns: HashSet<&str> = self
            .reader
            .tables
            .type_def
            .iter()
            .filter(|t| !t.type_namespace.is_empty())
            .map(|t| t.type_namespace.as_str())
            .collect();
        let mut result: Vec<String> = ns.drain().map(str::to_owned).collect();
        result.sort();
        result
    }

    /// Find all methods that have RVA 0 (abstract/extern).
    #[must_use]
    pub fn abstract_or_extern_methods(&self) -> Vec<MethodDef> {
        self.all_methods()
            .into_iter()
            .filter(|m| !m.has_body())
            .collect()
    }

    /// Find all types that implement a given interface by name.
    #[must_use]
    pub fn implementations_of(&self, interface_name: &str) -> Vec<TypeDef> {
        // Simplified: look through TypeRef to find the interface index, then
        // check InterfaceImpl table.
        let iface_coded_index = self
            .reader
            .tables
            .type_ref
            .iter()
            .enumerate()
            .find(|(_, r)| {
                r.type_name == interface_name || {
                    let fq = if r.type_namespace.is_empty() {
                        r.type_name.clone()
                    } else {
                        format!("{}.{}", r.type_namespace, r.type_name)
                    };
                    fq == interface_name
                }
            })
            .map(|(i, _)| ((u32::try_from(i).unwrap_or(u32::MAX) + 1) << 2) | 1); // TypeRef coded index

        iface_coded_index.map_or_else(Vec::new, |coded| {
            let implementing: HashSet<u32> = self
                .reader
                .tables
                .interface_impl
                .iter()
                .filter(|ii| ii.interface == coded)
                .map(|ii| ii.class)
                .collect();

            self.type_defs()
                .into_iter()
                .filter(|td| implementing.contains(&td.index))
                .collect()
        })
    }

    /// Count methods with a specific name (e.g. `".ctor"`).
    #[must_use]
    pub fn count_methods_named(&self, name: &str) -> usize {
        self.reader
            .tables
            .method_def
            .iter()
            .filter(|m| m.name == name)
            .count()
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AssemblyRefRow, AssemblyRow, MemberRefRow, MetadataHeaps, MetadataReader, MetadataRoot,
        MetadataTables, MethodDefRow, TypeDefRow,
    };

    fn make_reader_with_types(type_names: &[(&str, &str)]) -> MetadataReader {
        let mut tables = MetadataTables::default();
        let mut method_idx = 1u32;
        let mut field_idx = 1u32;
        for (ns, name) in type_names {
            tables.type_def.push(TypeDefRow {
                flags: 0x0001,
                type_name: name.to_string(),
                type_namespace: ns.to_string(),
                extends: 0,
                field_list: field_idx,
                method_list: method_idx,
            });
            method_idx += 1;
            field_idx += 1;
        }
        MetadataReader {
            root: MetadataRoot {
                major_version: 2,
                minor_version: 0,
                streams: vec![],
            },
            heaps: MetadataHeaps::default(),
            tables,
        }
    }

    fn make_reader_with_methods(methods: &[(&str, u32)]) -> MetadataReader {
        let mut tables = MetadataTables::default();
        tables.type_def.push(TypeDefRow {
            flags: 0x0001,
            type_name: "MyClass".into(),
            type_namespace: "MyNs".into(),
            extends: 0,
            field_list: 1,
            method_list: 1,
        });
        for (name, rva) in methods {
            tables.method_def.push(MethodDefRow {
                rva: *rva,
                impl_flags: 0,
                flags: 0x0086,
                name: name.to_string(),
                signature: vec![],
                param_list: 1,
            });
        }
        MetadataReader {
            root: MetadataRoot {
                major_version: 2,
                minor_version: 0,
                streams: vec![],
            },
            heaps: MetadataHeaps::default(),
            tables,
        }
    }

    // ── TypeDef ───────────────────────────────────────────────────────────────

    #[test]
    fn test_typedef_is_public() {
        let td = TypeDef {
            index: 1,
            namespace: "N".into(),
            name: "T".into(),
            flags: 0x0001,
            method_range: (1, 1),
            field_range: (1, 1),
            full_name: "N.T".into(),
        };
        assert!(td.is_public());
    }

    #[test]
    fn test_typedef_is_abstract() {
        let td = TypeDef {
            index: 1,
            namespace: String::new(),
            name: "Abstract".into(),
            flags: 0x0081,
            method_range: (1, 1),
            field_range: (1, 1),
            full_name: "Abstract".into(),
        };
        assert!(td.is_abstract());
    }

    #[test]
    fn test_typedef_is_interface() {
        let td = TypeDef {
            index: 1,
            namespace: String::new(),
            name: "IFoo".into(),
            flags: 0x00A1,
            method_range: (1, 3),
            field_range: (1, 1),
            full_name: "IFoo".into(),
        };
        assert!(td.is_interface());
        assert_eq!(td.method_count(), 2);
    }

    #[test]
    fn test_typedef_is_sealed() {
        let td = TypeDef {
            index: 1,
            namespace: String::new(),
            name: "Sealed".into(),
            flags: 0x0101,
            method_range: (1, 1),
            field_range: (1, 1),
            full_name: "Sealed".into(),
        };
        assert!(td.is_sealed());
    }

    #[test]
    fn test_typedef_full_name_with_namespace() {
        let reader = make_reader_with_types(&[("System", "Object")]);
        let full = MetadataFull::new(&reader);
        let types = full.type_defs();
        assert_eq!(types[0].full_name, "System.Object");
    }

    #[test]
    fn test_typedef_full_name_no_namespace() {
        let reader = make_reader_with_types(&[("", "Global")]);
        let full = MetadataFull::new(&reader);
        let types = full.type_defs();
        assert_eq!(types[0].full_name, "Global");
    }

    // ── MethodDef ─────────────────────────────────────────────────────────────

    #[test]
    fn test_methoddef_has_body() {
        let m = MethodDef {
            index: 1,
            declaring_type: 1,
            name: "Foo".into(),
            flags: 0x0086,
            impl_flags: 0,
            rva: 0x1000,
            signature: vec![],
            param_list: 1,
        };
        assert!(m.has_body());
    }

    #[test]
    fn test_methoddef_no_body() {
        let m = MethodDef {
            index: 1,
            declaring_type: 1,
            name: "Abstract".into(),
            flags: 0x04C6,
            impl_flags: 0,
            rva: 0,
            signature: vec![],
            param_list: 1,
        };
        assert!(!m.has_body());
        assert!(m.is_abstract());
    }

    #[test]
    fn test_methoddef_is_constructor() {
        let m = MethodDef {
            index: 1,
            declaring_type: 1,
            name: ".ctor".into(),
            flags: 0x0086,
            impl_flags: 0,
            rva: 0x100,
            signature: vec![],
            param_list: 1,
        };
        assert!(m.is_constructor());
    }

    #[test]
    fn test_methoddef_is_static() {
        let m = MethodDef {
            index: 1,
            declaring_type: 1,
            name: "Main".into(),
            flags: 0x0096,
            impl_flags: 0,
            rva: 0x100,
            signature: vec![],
            param_list: 1,
        };
        assert!(m.is_static());
    }

    // ── FieldDef ──────────────────────────────────────────────────────────────

    #[test]
    fn test_fielddef_is_public() {
        let f = FieldDef {
            index: 1,
            declaring_type: 1,
            name: "Value".into(),
            flags: 0x0006,
            signature: vec![],
        };
        assert!(f.is_public());
    }

    #[test]
    fn test_fielddef_is_static() {
        let f = FieldDef {
            index: 1,
            declaring_type: 1,
            name: "Count".into(),
            flags: 0x0016,
            signature: vec![],
        };
        assert!(f.is_static());
    }

    #[test]
    fn test_fielddef_is_literal() {
        let f = FieldDef {
            index: 1,
            declaring_type: 1,
            name: "MaxValue".into(),
            flags: 0x0056,
            signature: vec![],
        };
        assert!(f.is_literal());
    }

    // ── MetadataFull ──────────────────────────────────────────────────────────

    #[test]
    fn test_metadata_full_type_defs_empty() {
        let reader = make_reader_with_types(&[]);
        let full = MetadataFull::new(&reader);
        assert!(full.type_defs().is_empty());
    }

    #[test]
    fn test_metadata_full_type_defs_populated() {
        let reader = make_reader_with_types(&[("System", "String"), ("System", "Int32")]);
        let full = MetadataFull::new(&reader);
        assert_eq!(full.type_defs().len(), 2);
    }

    #[test]
    fn test_metadata_full_find_type_found() {
        let reader = make_reader_with_types(&[("System", "String")]);
        let full = MetadataFull::new(&reader);
        assert!(full.find_type("System.String").is_some());
    }

    #[test]
    fn test_metadata_full_find_type_not_found() {
        let reader = make_reader_with_types(&[("System", "String")]);
        let full = MetadataFull::new(&reader);
        assert!(full.find_type("System.Unknown").is_none());
    }

    #[test]
    fn test_metadata_full_methods_of_type() {
        let reader = make_reader_with_methods(&[(".ctor", 0x100), ("Run", 0x200)]);
        let full = MetadataFull::new(&reader);
        let methods = full.methods_of_type(1);
        assert_eq!(methods.len(), 2);
    }

    #[test]
    fn test_metadata_full_all_methods() {
        let reader = make_reader_with_methods(&[(".ctor", 0x100), ("ToString", 0x200)]);
        let full = MetadataFull::new(&reader);
        assert!(!full.all_methods().is_empty());
    }

    #[test]
    fn test_metadata_full_stats() {
        let reader = make_reader_with_types(&[("A", "B")]);
        let full = MetadataFull::new(&reader);
        let stats = full.stats();
        assert_eq!(stats.type_def_count, 1);
    }

    #[test]
    fn test_metadata_full_namespaces() {
        let reader = make_reader_with_types(&[("System", "Object"), ("System.IO", "File")]);
        let full = MetadataFull::new(&reader);
        let ns = full.namespaces();
        assert!(ns.contains(&"System".to_string()));
    }

    #[test]
    fn test_metadata_full_assembly_info_none_when_empty() {
        let reader = make_reader_with_types(&[]);
        let full = MetadataFull::new(&reader);
        assert!(full.assembly_info().is_none());
    }

    #[test]
    fn test_metadata_full_assembly_info_some() {
        let mut reader = make_reader_with_types(&[]);
        reader.tables.assembly.push(AssemblyRow {
            hash_alg_id: 0x8004,
            major_version: 1,
            minor_version: 0,
            build_number: 0,
            revision_number: 0,
            flags: 0,
            public_key: vec![],
            name: "MyApp".into(),
            culture: String::new(),
        });
        let full = MetadataFull::new(&reader);
        let info = full.assembly_info().unwrap();
        assert_eq!(info.name, "MyApp");
        assert_eq!(info.version_string(), "1.0.0.0");
    }

    #[test]
    fn test_metadata_full_assembly_refs() {
        let mut reader = make_reader_with_types(&[]);
        reader.tables.assembly_ref.push(AssemblyRefRow {
            major_version: 4,
            minor_version: 0,
            build_number: 0,
            revision_number: 0,
            flags: 0,
            public_key_or_token: vec![0xb7, 0x7a],
            name: "mscorlib".into(),
            culture: String::new(),
            hash_value: vec![],
        });
        let full = MetadataFull::new(&reader);
        let refs = full.assembly_refs();
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].name, "mscorlib");
    }

    #[test]
    fn test_metadata_full_count_methods_named() {
        let reader =
            make_reader_with_methods(&[(".ctor", 0x100), (".ctor", 0x200), ("Run", 0x300)]);
        let full = MetadataFull::new(&reader);
        assert_eq!(full.count_methods_named(".ctor"), 2);
    }

    #[test]
    fn test_metadata_full_abstract_methods() {
        let reader = make_reader_with_methods(&[("Abstract", 0), ("Concrete", 0x100)]);
        let full = MetadataFull::new(&reader);
        let abs = full.abstract_or_extern_methods();
        assert_eq!(abs.len(), 1);
        assert_eq!(abs[0].name, "Abstract");
    }

    #[test]
    fn test_decl_security_is_demand() {
        let ds = DeclSecurity {
            index: 1,
            action: 2,
            parent: 0,
            permission_set: vec![1],
        };
        assert!(ds.is_demand());
        assert!(ds.has_permissions());
    }

    #[test]
    fn test_type_spec_is_generic() {
        let ts = TypeSpec {
            index: 1,
            signature: vec![0x15, 0x11, 0x01, 0x01, 0x08],
        };
        assert!(ts.is_generic_instantiation());
    }

    #[test]
    fn test_type_spec_not_generic() {
        let ts = TypeSpec {
            index: 1,
            signature: vec![0x12, 0x01],
        };
        assert!(!ts.is_generic_instantiation());
    }

    #[test]
    fn test_assembly_info_version_string() {
        let info = AssemblyInfo {
            name: "Test".into(),
            culture: String::new(),
            version: (2, 3, 4, 5),
            has_strong_name: false,
            hash_alg_id: 0,
        };
        assert_eq!(info.version_string(), "2.3.4.5");
        assert!(info.is_neutral_culture());
    }

    #[test]
    fn test_assembly_ref_info_version_string() {
        let r = AssemblyRefInfo {
            index: 1,
            name: "mscorlib".into(),
            culture: String::new(),
            version: (4, 0, 0, 0),
            has_public_key_token: true,
        };
        assert_eq!(r.version_string(), "4.0.0.0");
    }

    #[test]
    fn test_metadata_stats_serialization() {
        let stats = MetadataStats {
            type_def_count: 10,
            method_def_count: 50,
            field_count: 20,
            type_ref_count: 30,
            member_ref_count: 40,
            custom_attribute_count: 5,
            assembly_ref_count: 3,
            generic_param_count: 7,
            method_spec_count: 2,
            type_spec_count: 8,
            decl_security_count: 1,
        };
        let json = serde_json::to_string(&stats).unwrap();
        let d: MetadataStats = serde_json::from_str(&json).unwrap();
        assert_eq!(d.type_def_count, 10);
    }

    #[test]
    fn test_member_refs_empty() {
        let reader = make_reader_with_types(&[]);
        let full = MetadataFull::new(&reader);
        assert!(full.member_refs().is_empty());
    }

    #[test]
    fn test_find_member_refs() {
        let mut reader = make_reader_with_types(&[]);
        reader.tables.member_ref.push(MemberRefRow {
            class: 0,
            name: "WriteLine".into(),
            signature: vec![],
        });
        reader.tables.member_ref.push(MemberRefRow {
            class: 0,
            name: "ReadLine".into(),
            signature: vec![],
        });
        let full = MetadataFull::new(&reader);
        assert_eq!(full.find_member_refs("Line").len(), 2);
        assert_eq!(full.find_member_refs("Write").len(), 1);
    }
}
