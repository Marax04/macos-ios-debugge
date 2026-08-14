//! `type_injector` — Inject new types into .NET assemblies: `TypeDef` rows,
//! `FieldDef` rows, `MethodDef` stubs, `TypeInjector`, `InjectedType`, `FieldSpec`.

use std::collections::HashMap;

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};

// ─── Visibility / accessibility flags ────────────────────────────────────────

/// `TypeDef` visibility flags (ECMA-335 §II.23.1.15).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TypeVisibility {
    /// `NotPublic` = 0x00000000
    NotPublic,
    /// Public = 0x00000001
    Public,
    /// `NestedPublic` = 0x00000002
    NestedPublic,
    /// `NestedPrivate` = 0x00000003
    NestedPrivate,
    /// `NestedFamily` = 0x00000004
    NestedFamily,
    /// `NestedAssembly` = 0x00000005
    NestedAssembly,
    /// `NestedFamAndAssem` = 0x00000006
    NestedFamAndAssem,
    /// `NestedFamOrAssem` = 0x00000007
    NestedFamOrAssem,
}

impl TypeVisibility {
    /// The raw flag bits.
    #[must_use]
    pub const fn bits(self) -> u32 {
        match self {
            Self::NotPublic => 0x00000000,
            Self::Public => 0x00000001,
            Self::NestedPublic => 0x00000002,
            Self::NestedPrivate => 0x00000003,
            Self::NestedFamily => 0x00000004,
            Self::NestedAssembly => 0x00000005,
            Self::NestedFamAndAssem => 0x00000006,
            Self::NestedFamOrAssem => 0x00000007,
        }
    }
}

/// `TypeDef` layout flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TypeLayout {
    Auto,
    Sequential,
    Explicit,
}

impl TypeLayout {
    #[must_use]
    pub const fn bits(self) -> u32 {
        match self {
            Self::Auto => 0x00000000,
            Self::Sequential => 0x00000008,
            Self::Explicit => 0x00000010,
        }
    }
}

/// `TypeDef` semantic flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TypeSemantics {
    Class,
    Interface,
}

impl TypeSemantics {
    #[must_use]
    pub const fn bits(self) -> u32 {
        match self {
            Self::Class => 0x00000000,
            Self::Interface => 0x00000020,
        }
    }
}

// ─── FieldSpec ────────────────────────────────────────────────────────────────

/// Specification for a field to inject into a type.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldSpec {
    /// Field name.
    pub name: String,
    /// Field flags (ECMA-335 §II.23.1.5).
    pub flags: u16,
    /// Element type byte (see ECMA-335 §II.23.1.16 `ELEMENT_TYPE`_*).
    pub element_type: u8,
    /// For object/class fields: full type name (e.g. `"System.String"`).
    pub type_name: Option<String>,
    /// Initial constant value (optional).
    pub default_value: Option<Vec<u8>>,
    /// Whether this field is static.
    pub is_static: bool,
}

impl FieldSpec {
    /// Create a public instance field of the given element type.
    #[must_use]
    pub fn public_instance(name: impl Into<String>, element_type: u8) -> Self {
        Self {
            name: name.into(),
            flags: 0x0006, // Public
            element_type,
            type_name: None,
            default_value: None,
            is_static: false,
        }
    }

    /// Create a public static field.
    #[must_use]
    pub fn public_static(name: impl Into<String>, element_type: u8) -> Self {
        Self {
            name: name.into(),
            flags: 0x0016, // Public | Static
            element_type,
            type_name: None,
            default_value: None,
            is_static: true,
        }
    }

    /// Create a private instance field.
    #[must_use]
    pub fn private_instance(name: impl Into<String>, element_type: u8) -> Self {
        Self {
            name: name.into(),
            flags: 0x0002, // Private
            element_type,
            type_name: None,
            default_value: None,
            is_static: false,
        }
    }

    /// Encode the field signature blob (ECMA-335 §II.23.2.4).
    #[must_use]
    pub fn encode_signature(&self) -> Vec<u8> {
        // FIELD calling convention = 0x06
        vec![0x06, self.element_type]
    }

    /// Return the raw flags u16.
    #[must_use]
    pub const fn raw_flags(&self) -> u16 {
        let mut f = self.flags;
        if self.is_static {
            f |= 0x0010; // Static
        }
        f
    }
}

// ─── MethodSpec ───────────────────────────────────────────────────────────────

/// Specification for a method stub to inject.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MethodSpec {
    /// Method name.
    pub name: String,
    /// Method flags.
    pub flags: u16,
    /// Implementation flags.
    pub impl_flags: u16,
    /// Return type element type byte.
    pub return_type: u8,
    /// Parameter type element type bytes.
    pub param_types: Vec<u8>,
    /// Parameter names.
    pub param_names: Vec<String>,
    /// Whether to include a minimal `ret` body.
    pub include_body: bool,
}

impl MethodSpec {
    /// Create a public static void method with no parameters.
    #[must_use]
    pub fn public_static_void(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            flags: 0x0016, // Public | Static
            impl_flags: 0,
            return_type: 0x01, // Void
            param_types: Vec::new(),
            param_names: Vec::new(),
            include_body: true,
        }
    }

    /// Create a public instance void method.
    #[must_use]
    pub fn public_instance_void(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            flags: 0x0006, // Public
            impl_flags: 0,
            return_type: 0x01,
            param_types: Vec::new(),
            param_names: Vec::new(),
            include_body: true,
        }
    }

    /// Encode the method signature blob.
    #[must_use]
    pub fn encode_signature(&self) -> Vec<u8> {
        let is_instance = (self.flags & 0x0010) == 0;
        let calling_conv: u8 = if is_instance { 0x20 } else { 0x00 };
        let mut sig = vec![calling_conv, self.param_types.len() as u8, self.return_type];
        sig.extend_from_slice(&self.param_types);
        sig
    }

    /// Encode a minimal method body (tiny format, just `ret`).
    #[must_use]
    pub fn encode_body(&self) -> Vec<u8> {
        if !self.include_body {
            return Vec::new();
        }
        // Tiny header: ((code_size) << 2) | 0x02; code = `ret` = 0x2A
        vec![0x06, 0x2A] // tiny header (1 byte code) | ret
    }
}

// ─── InjectedType ─────────────────────────────────────────────────────────────

/// Represents a type that has been (or will be) injected into an assembly.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InjectedType {
    /// Simple type name (without namespace).
    pub name: String,
    /// Namespace.
    pub namespace: String,
    /// Computed `TypeDef` flags.
    pub flags: u32,
    /// Base type full name (e.g. `"System.Object"`).
    pub base_type: Option<String>,
    /// Interfaces this type implements.
    pub interfaces: Vec<String>,
    /// Fields injected into this type.
    pub fields: Vec<FieldSpec>,
    /// Methods injected into this type.
    pub methods: Vec<MethodSpec>,
    /// The 1-based `TypeDef` row index assigned after injection, if known.
    pub assigned_row: Option<usize>,
    /// Whether the type was successfully committed to the editor.
    pub committed: bool,
}

impl InjectedType {
    /// Fully-qualified name.
    #[must_use]
    pub fn full_name(&self) -> String {
        if self.namespace.is_empty() {
            self.name.clone()
        } else {
            format!("{}.{}", self.namespace, self.name)
        }
    }

    /// Add a field to this type.
    pub fn add_field(&mut self, field: FieldSpec) {
        self.fields.push(field);
    }

    /// Add a method to this type.
    pub fn add_method(&mut self, method: MethodSpec) {
        self.methods.push(method);
    }

    /// Number of fields.
    #[must_use]
    pub fn field_count(&self) -> usize {
        self.fields.len()
    }

    /// Number of methods.
    #[must_use]
    pub fn method_count(&self) -> usize {
        self.methods.len()
    }
}

// ─── InjectionPlan ────────────────────────────────────────────────────────────

/// Represents a complete set of types to inject, checked for consistency
/// before any mutations are applied.
#[derive(Debug, Default, Clone)]
pub struct InjectionPlan {
    /// Types to inject, keyed by full name.
    types: Vec<InjectedType>,
    /// Dependency order: types that must be injected before others.
    dep_order: Vec<String>,
}

impl InjectionPlan {
    /// Create an empty plan.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a type to the plan.
    ///
    /// # Errors
    /// Returns an error if a type with the same full name already exists in the plan.
    pub fn add_type(&mut self, t: InjectedType) -> Result<()> {
        let fqn = t.full_name();
        if self.types.iter().any(|x| x.full_name() == fqn) {
            return Err(anyhow!("duplicate type in injection plan: {fqn}"));
        }
        self.dep_order.push(fqn);
        self.types.push(t);
        Ok(())
    }

    /// Return types in dependency order.
    #[must_use]
    pub fn ordered_types(&self) -> Vec<&InjectedType> {
        self.dep_order
            .iter()
            .filter_map(|name| self.types.iter().find(|t| &t.full_name() == name))
            .collect()
    }

    /// Number of types in the plan.
    #[must_use]
    pub fn len(&self) -> usize {
        self.types.len()
    }

    /// Returns `true` if there are no types in the plan.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.types.is_empty()
    }

    /// Validate the plan: check for unknown base types and circular deps.
    #[must_use] 
    pub fn validate(&self) -> Vec<String> {
        let mut issues = Vec::new();
        let known: std::collections::HashSet<String> =
            self.types.iter().map(InjectedType::full_name).collect();

        for t in &self.types {
            for iface in &t.interfaces {
                if !known.contains(iface.as_str()) && !is_well_known_type(iface) {
                    issues.push(format!(
                        "type {} implements unknown interface {}",
                        t.full_name(),
                        iface
                    ));
                }
            }
        }
        issues
    }
}

fn is_well_known_type(name: &str) -> bool {
    const KNOWN: &[&str] = &[
        "System.Object",
        "System.ValueType",
        "System.Enum",
        "System.Attribute",
        "System.Exception",
        "System.IDisposable",
        "System.IComparable",
        "System.IEquatable`1",
        "System.Collections.IEnumerable",
        "System.Collections.Generic.IEnumerable`1",
    ];
    KNOWN.contains(&name)
}

// ─── TypeInjector ─────────────────────────────────────────────────────────────

/// Injects new types into a .NET assembly's metadata tables.
///
/// Works with raw [`Vec<u8>`] representing table row data rather than the
/// full `AssemblyEditor`, so it can be used stand-alone for low-level patching.
pub struct TypeInjector {
    /// Injected types tracked by full name.
    injected: HashMap<String, InjectedType>,
    /// Next avai`TypeDef`ypeDef row index (1-based).
    next_typedef_idx: usize,
    /// Next avai`FieldDef`eldDef row index.
    next_fielddef_idx: usize,
    /// Next avai`MethodDef`hodDef row index.
    next_methoddef_idx: usize,
    /// Accumu`TypeDef`ypeDef row blobs (raw encoded data).
    typedef_rows: Vec<TypeDefRowData>,
    /// Accumu`FieldDef`eldDef row blobs.
    fielddef_rows: Vec<FieldDefRowData>,
    /// Accumu`MethodDef`hodDef row blobs.
    methoddef_rows: Vec<MethodDefRowData>,
}

/// Raw en`TypeDef`ypeDef row data.
#[derive(Debug, Clone)]
pub struct TypeDefRowData {
    pub flags: u32,
    pub type_name: String,
    pub type_namespace: String,
    pub extends_coded: u32,
    pub field_list: u32,
    pub method_list: u32,
}

/// Raw en`FieldDef`eldDef row data.
#[derive(Debug, Clone)]
pub struct FieldDefRowData {
    pub flags: u16,
    pub name: String,
    pub signature: Vec<u8>,
}

/// Raw en`MethodDef`hodDef row data.
#[derive(Debug, Clone)]
pub struct MethodDefRowData {
    pub rva: u32,
    pub impl_flags: u16,
    pub flags: u16,
    pub name: String,
    pub signature: Vec<u8>,
    pub param_list: u32,
    pub body: Vec<u8>,
}

impl TypeInjector {
    /// Create a new injector, starting at the given next-row indices.
    #[must_use]
    pub fn new(
        next_typedef_idx: usize,
        next_fielddef_idx: usize,
        next_methoddef_idx: usize,
    ) -> Self {
        Self {
            injected: HashMap::new(),
            next_typedef_idx,
            next_fielddef_idx,
            next_methoddef_idx,
            typedef_rows: Vec::new(),
            fielddef_rows: Vec::new(),
            methoddef_rows: Vec::new(),
        }
    }

    /// Inject a type from an [`InjectedType`] spec.
    ///
    /// Allo`TypeDef`yp`FieldDef`eldDef`MethodDef`hodDef row indices and records the
    /// raw row data.  Returns the assigned 1-`TypeDef`ypeDef row index.
    ///
    /// # Errors
    /// Returns an error if the type has already been injected.
    pub fn inject(&mut self, mut t: InjectedType) -> Result<usize> {
        let fqn = t.full_name();
        if self.injected.contains_key(&fqn) {
            return Err(anyhow!("type already injected: {fqn}"));
        }

        let typedef_idx = self.next_typedef_idx;
        let field_list = self.next_fielddef_idx as u32;
        let method_list = self.next_methoddef_idx as u32;

        // Encode fields
        for field in &t.fields {
            self.fielddef_rows.push(FieldDefRowData {
                flags: field.raw_flags(),
                name: field.name.clone(),
                signature: field.encode_signature(),
            });
            self.next_fielddef_idx += 1;
        }

        // Encode methods
        let mut current_param_list = 1u32;
        for method in &t.methods {
            let body = method.encode_body();
            self.methoddef_rows.push(MethodDefRowData {
                rva: 0, // RVA assigned by the serializer
                impl_flags: method.impl_flags,
                flags: method.flags,
                name: method.name.clone(),
                signature: method.encode_signature(),
                param_list: current_param_list,
                body,
            });
            current_param_list += method.param_names.len() as u32;
            self.next_methoddef_idx += 1;
        }

        // Encode the TypeDef row
        let flags = compute_typedef_flags(t.flags, &t);
        self.typedef_rows.push(TypeDefRowData {
            flags,
            type_name: t.name.clone(),
            type_namespace: t.namespace.clone(),
            extends_coded: 0, // resolved later
            field_list,
            method_list,
        });

        t.assigned_row = Some(typedef_idx);
        t.committed = true;
        self.injected.insert(fqn, t);
        self.next_typedef_idx += 1;

        Ok(typedef_idx)
    }

    /// Inject all types from a plan in dependency order.
    ///
    /// # Errors
    /// Returns an error if any type fails to inject.
    pub fn inject_plan(&mut self, plan: &InjectionPlan) -> Result<Vec<usize>> {
        let mut indices = Vec::new();
        for t in plan.ordered_types() {
            let idx = self.inject(t.clone())?;
            indices.push(idx);
        }
        Ok(indices)
    }

    /// Look up an injected type by full name.
    #[must_use]
    pub fn find(&self, full_name: &str) -> Option<&InjectedType> {
        self.injected.get(full_name)
    }

    /// All injected type full names.
    #[must_use]
    pub fn injected_names(&self) -> Vec<&str> {
        self.injected.keys().map(std::string::String::as_str).collect()
    }

    /// Number of injected types.
    #[must_use]
    pub fn type_count(&self) -> usize {
        self.injected.len()
    }

    /// Accumulated TypeDef rows.
    #[must_use]
    pub fn typedef_rows(&self) -> &[TypeDefRowData] {
        &self.typedef_rows
    }

    /// Accumulated FieldDef rows.
    #[must_use]
    pub fn fielddef_rows(&self) -> &[FieldDefRowData] {
        &self.fielddef_rows
    }

    /// Accumulated MethodDef rows.
    #[must_use]
    pub fn methoddef_rows(&self) -> &[MethodDefRowData] {
        &self.methoddef_rows
    }

    /// Reset all state; useful for re-using the injector.
    pub fn reset(&mut self) {
        self.injected.clear();
        self.typedef_rows.clear();
        self.fielddef_rows.clear();
        self.methoddef_rows.clear();
    }

    /// Serialize all TypeDef rows to a compact binary representation
    /// (suitable for comparison / diffing, not a real metadata stream).
    #[must_use]
    pub fn serialize_typedef_rows(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for row in &self.typedef_rows {
            out.extend_from_slice(&row.flags.to_le_bytes());
            encode_str_field(&row.type_name, &mut out);
            encode_str_field(&row.type_namespace, &mut out);
            out.extend_from_slice(&row.field_list.to_le_bytes());
            out.extend_from_slice(&row.method_list.to_le_bytes());
        }
        out
    }
}

fn compute_typedef_flags(base_flags: u32, t: &InjectedType) -> u32 {
    let mut f = base_flags;
    // Ensure visibility is set
    if f & 0x07 == 0 {
        f |= TypeVisibility::Public.bits();
    }
    // Interfaces must have the interface bit
    if t.fields.is_empty() && t.methods.iter().all(|m| m.flags & 0x0400 != 0) {
        f |= TypeSemantics::Interface.bits();
    }
    f
}

fn encode_str_field(s: &str, out: &mut Vec<u8>) {
    let bytes = s.as_bytes();
    out.extend_from_slice(&(bytes.len() as u16).to_le_bytes());
    out.extend_from_slice(bytes);
}

// ─── TypeBuilder ──────────────────────────────────────────────────────────────

/// Fluent builder for [`InjectedType`].
#[derive(Debug, Default)]
pub struct TypeBuilder {
    name: String,
    namespace: String,
    visibility: u32,
    layout: u32,
    semantics: u32,
    extra_flags: u32,
    base_type: Option<String>,
    interfaces: Vec<String>,
    fields: Vec<FieldSpec>,
    methods: Vec<MethodSpec>,
}

impl TypeBuilder {
    /// Start building a type with the given simple name.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            visibility: TypeVisibility::Public.bits(),
            ..Default::default()
        }
    }

    /// Set the namespace.
    #[must_use]
    pub fn namespace(mut self, ns: impl Into<String>) -> Self {
        self.namespace = ns.into();
        self
    }

    /// Set visibility.
    #[must_use]
    pub const fn visibility(mut self, v: TypeVisibility) -> Self {
        self.visibility = v.bits();
        self
    }

    /// Set layout.
    #[must_use]
    pub const fn layout(mut self, l: TypeLayout) -> Self {
        self.layout = l.bits();
        self
    }

    /// Set as interface.
    #[must_use]
    pub fn interface(mut self) -> Self {
        self.semantics = TypeSemantics::Interface.bits();
        self.extra_flags |= 0x00000080; // Abstract
        self
    }

    /// Set base type.
    #[must_use]
    pub fn extends(mut self, base: impl Into<String>) -> Self {
        self.base_type = Some(base.into());
        self
    }

    /// Implement an interface.
    #[must_use]
    pub fn implements(mut self, iface: impl Into<String>) -> Self {
        self.interfaces.push(iface.into());
        self
    }

    /// Add a field.
    #[must_use]
    pub fn field(mut self, f: FieldSpec) -> Self {
        self.fields.push(f);
        self
    }

    /// Add a method.
    #[must_use]
    pub fn method(mut self, m: MethodSpec) -> Self {
        self.methods.push(m);
        self
    }

    /// Finalise into an [`InjectedType`].
    #[must_use]
    pub fn build(self) -> InjectedType {
        let flags = self.visibility | self.layout | self.semantics | self.extra_flags;
        InjectedType {
            name: self.name,
            namespace: self.namespace,
            flags,
            base_type: self.base_type,
            interfaces: self.interfaces,
            fields: self.fields,
            methods: self.methods,
            assigned_row: None,
            committed: false,
        }
    }
}
