//! Extended IL editor — `IlEditorExtended` with high-level mutation primitives.
//!
//! Builds on top of the base `AssemblyEditor` to provide a richer API for
//! complex transformations: patch sets, method redirection, field/class
//! injection, attribute editing, resource patching, and type forwarding.

use std::collections::HashMap;
use std::fmt;

// ─── Error ────────────────────────────────────────────────────────────────────

/// Errors that can arise from extended IL editing operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExtendedEditError {
    /// The target type was not found.
    TypeNotFound(String),
    /// The target method was not found.
    MethodNotFound { type_name: String, method_name: String },
    /// The target field was not found.
    FieldNotFound { type_name: String, field_name: String },
    /// A patch conflict: two patches target the same offset.
    PatchConflict { offset: u32 },
    /// A type forwarder for the given type already exists.
    ForwarderExists(String),
    /// The attribute to remove was not present.
    AttributeNotFound { target: String, attr_type: String },
    /// A resource with the given name was not found.
    ResourceNotFound(String),
    /// Generic/custom error.
    Custom(String),
}

impl fmt::Display for ExtendedEditError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TypeNotFound(n) => write!(f, "type not found: {n}"),
            Self::MethodNotFound { type_name, method_name } => {
                write!(f, "method {method_name} not found on {type_name}")
            }
            Self::FieldNotFound { type_name, field_name } => {
                write!(f, "field {field_name} not found on {type_name}")
            }
            Self::PatchConflict { offset } => write!(f, "patch conflict at offset 0x{offset:04X}"),
            Self::ForwarderExists(n) => write!(f, "type forwarder already exists for {n}"),
            Self::AttributeNotFound { target, attr_type } => {
                write!(f, "attribute {attr_type} not found on {target}")
            }
            Self::ResourceNotFound(n) => write!(f, "resource not found: {n}"),
            Self::Custom(s) => write!(f, "{s}"),
        }
    }
}

impl std::error::Error for ExtendedEditError {}

pub type Result<T> = std::result::Result<T, ExtendedEditError>;

// ─── PatchEntry ───────────────────────────────────────────────────────────────

/// A single byte-level patch to apply to the raw assembly stream.
#[derive(Debug, Clone)]
pub struct PatchEntry {
    /// File offset at which to apply the patch.
    pub offset: u32,
    /// Original bytes at that offset (for verification / reverting).
    pub original_bytes: Vec<u8>,
    /// New bytes to write.
    pub new_bytes: Vec<u8>,
    /// Human-readable description.
    pub description: String,
    /// Whether this patch has been applied.
    pub applied: bool,
}

impl PatchEntry {
    #[must_use]
    pub fn new(offset: u32, original: Vec<u8>, new_bytes: Vec<u8>, description: impl Into<String>) -> Self {
        Self {
            offset,
            original_bytes: original,
            new_bytes,
            description: description.into(),
            applied: false,
        }
    }

    /// Return the number of bytes this patch modifies.
    #[must_use]
    pub const fn patch_size(&self) -> usize {
        self.new_bytes.len()
    }

    /// Returns `true` if the original and new bytes differ.
    #[must_use]
    pub fn has_changes(&self) -> bool {
        self.original_bytes != self.new_bytes
    }
}

// ─── PatchSet ─────────────────────────────────────────────────────────────────

/// A set of byte-level patches that can be applied atomically.
#[derive(Debug, Default, Clone)]
pub struct PatchSet {
    entries: Vec<PatchEntry>,
}

impl PatchSet {
    /// Create an empty patch set.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a patch entry, returning an error if it overlaps an existing patch.
    pub fn add(&mut self, entry: PatchEntry) -> Result<()> {
        // Check for overlap with existing patches.
        for existing in &self.entries {
            let a_start = entry.offset as usize;
            let a_end = a_start + entry.new_bytes.len();
            let b_start = existing.offset as usize;
            let b_end = b_start + existing.new_bytes.len();
            if a_start < b_end && b_start < a_end {
                return Err(ExtendedEditError::PatchConflict { offset: entry.offset });
            }
        }
        self.entries.push(entry);
        Ok(())
    }

    /// Apply all patches to a raw byte buffer.
    pub fn apply_to(&self, buffer: &mut Vec<u8>) -> usize {
        let mut applied = 0;
        for entry in &self.entries {
            let start = entry.offset as usize;
            let end = start + entry.new_bytes.len();
            if end <= buffer.len() {
                buffer[start..end].copy_from_slice(&entry.new_bytes);
                applied += 1;
            }
        }
        applied
    }

    /// Revert all patches from a raw byte buffer (restore originals).
    pub fn revert_from(&self, buffer: &mut Vec<u8>) -> usize {
        let mut reverted = 0;
        for entry in self.entries.iter().rev() {
            let start = entry.offset as usize;
            let end = start + entry.original_bytes.len();
            if end <= buffer.len() {
                buffer[start..end].copy_from_slice(&entry.original_bytes);
                reverted += 1;
            }
        }
        reverted
    }

    /// Number of patches in this set.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` if there are no patches.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Clear all patches.
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// Total bytes modified by all patches.
    #[must_use]
    pub fn total_bytes_modified(&self) -> usize {
        self.entries.iter().map(PatchEntry::patch_size).sum()
    }
}

// ─── MethodRedirection ───────────────────────────────────────────────────────

/// A method-level redirection that replaces a call target with another.
#[derive(Debug, Clone)]
pub struct MethodRedirection {
    /// Type name containing the method to redirect.
    pub source_type: String,
    /// Method to redirect (original name).
    pub source_method: String,
    /// Type name of the replacement method.
    pub target_type: String,
    /// Replacement method name.
    pub target_method: String,
    /// Whether to redirect calls (as opposed to replacing the body entirely).
    pub redirect_calls: bool,
    /// Optional IL body to substitute instead of redirecting.
    pub substitute_body: Option<Vec<u8>>,
    /// Whether this redirection has been applied.
    pub applied: bool,
}

impl MethodRedirection {
    /// Create a call-level redirection from one method to another.
    #[must_use]
    pub fn new_call_redirect(
        source_type: impl Into<String>,
        source_method: impl Into<String>,
        target_type: impl Into<String>,
        target_method: impl Into<String>,
    ) -> Self {
        Self {
            source_type: source_type.into(),
            source_method: source_method.into(),
            target_type: target_type.into(),
            target_method: target_method.into(),
            redirect_calls: true,
            substitute_body: None,
            applied: false,
        }
    }

    /// Create a body-substitution redirection.
    #[must_use]
    pub fn new_body_substitute(
        source_type: impl Into<String>,
        source_method: impl Into<String>,
        body_il: Vec<u8>,
    ) -> Self {
        Self {
            source_type: source_type.into(),
            source_method: source_method.into(),
            target_type: String::new(),
            target_method: String::new(),
            redirect_calls: false,
            substitute_body: Some(body_il),
            applied: false,
        }
    }

    /// Mark this redirection as applied.
    pub const fn mark_applied(&mut self) {
        self.applied = true;
    }

    /// Returns a description of this redirection.
    #[must_use]
    pub fn describe(&self) -> String {
        if self.redirect_calls {
            format!(
                "redirect {}::{} -> {}::{}",
                self.source_type, self.source_method,
                self.target_type, self.target_method,
            )
        } else {
            format!("substitute body of {}::{}", self.source_type, self.source_method)
        }
    }
}

// ─── FieldInjector ───────────────────────────────────────────────────────────

/// Specification for injecting a new field into an existing type.
#[derive(Debug, Clone)]
pub struct FieldInjector {
    /// Type to inject into.
    pub target_type: String,
    /// Name of the new field.
    pub field_name: String,
    /// Type of the new field (as element-type byte).
    pub field_type_sig: Vec<u8>,
    /// Access flags (e.g. 0x0006 = public).
    pub flags: u16,
    /// Optional default / constant value.
    pub default_value: Option<Vec<u8>>,
    /// Custom attributes to add to the new field.
    pub custom_attributes: Vec<(String, Vec<u8>)>,
}

impl FieldInjector {
    /// Create a public instance field injector.
    #[must_use]
    pub fn public_instance(
        target_type: impl Into<String>,
        field_name: impl Into<String>,
        element_type: u8,
    ) -> Self {
        Self {
            target_type: target_type.into(),
            field_name: field_name.into(),
            field_type_sig: vec![0x06, element_type],
            flags: 0x0006,
            default_value: None,
            custom_attributes: Vec::new(),
        }
    }

    /// Create a public static field injector.
    #[must_use]
    pub fn public_static(
        target_type: impl Into<String>,
        field_name: impl Into<String>,
        element_type: u8,
    ) -> Self {
        Self {
            target_type: target_type.into(),
            field_name: field_name.into(),
            field_type_sig: vec![0x06, element_type],
            flags: 0x0016,
            default_value: None,
            custom_attributes: Vec::new(),
        }
    }

    /// Add a custom attribute to the injected field.
    pub fn add_custom_attribute(&mut self, attr_type: impl Into<String>, data: Vec<u8>) {
        self.custom_attributes.push((attr_type.into(), data));
    }
}

// ─── ClassInjector ───────────────────────────────────────────────────────────

/// Specification for injecting a new class into the assembly.
#[derive(Debug, Clone)]
pub struct ClassInjector {
    /// Namespace of the new class.
    pub namespace: String,
    /// Name of the new class.
    pub class_name: String,
    /// `TypeDef` flags (e.g. 0x00000101 = public sealed).
    pub flags: u32,
    /// Base type name (empty for `System.Object`).
    pub base_type: String,
    /// Interfaces to implement.
    pub interfaces: Vec<String>,
    /// Methods to add to the new class.
    pub methods: Vec<InjectedMethod>,
    /// Fields to add to the new class.
    pub fields: Vec<FieldInjector>,
    /// Custom attributes.
    pub custom_attributes: Vec<(String, Vec<u8>)>,
}

/// A method to inject as part of a `ClassInjector`.
#[derive(Debug, Clone)]
pub struct InjectedMethod {
    pub name: String,
    pub flags: u16,
    pub return_type_sig: Vec<u8>,
    pub param_types: Vec<Vec<u8>>,
    pub param_names: Vec<String>,
    pub il_body: Vec<u8>,
}

impl InjectedMethod {
    /// Create a simple `void` method with a `ret` body.
    #[must_use]
    pub fn void_method(name: impl Into<String>, flags: u16) -> Self {
        Self {
            name: name.into(),
            flags,
            return_type_sig: vec![0x01], // void
            param_types: Vec::new(),
            param_names: Vec::new(),
            il_body: vec![0x2A], // ret
        }
    }
}

impl ClassInjector {
    /// Create a public sealed class injector.
    #[must_use]
    pub fn public_sealed(namespace: impl Into<String>, class_name: impl Into<String>) -> Self {
        Self {
            namespace: namespace.into(),
            class_name: class_name.into(),
            flags: 0x00000101,
            base_type: "System.Object".into(),
            interfaces: Vec::new(),
            methods: Vec::new(),
            fields: Vec::new(),
            custom_attributes: Vec::new(),
        }
    }

    /// Full name of the injected class.
    #[must_use]
    pub fn full_name(&self) -> String {
        if self.namespace.is_empty() {
            self.class_name.clone()
        } else {
            format!("{}.{}", self.namespace, self.class_name)
        }
    }

    /// Add a method to the injected class.
    pub fn add_method(&mut self, method: InjectedMethod) {
        self.methods.push(method);
    }
}

// ─── AttributeEditor ─────────────────────────────────────────────────────────

/// An attribute mutation to apply to a type, method, or field.
#[derive(Debug, Clone)]
pub enum AttributeEdit {
    /// Add a custom attribute with the given type and blob.
    Add { target: String, attr_type: String, blob: Vec<u8> },
    /// Remove all custom attributes of the given type from a target.
    Remove { target: String, attr_type: String },
    /// Replace all instances of an attribute with a new one.
    Replace { target: String, old_type: String, new_type: String, new_blob: Vec<u8> },
}

/// Manages a queue of attribute edits.
#[derive(Debug, Default)]
pub struct AttributeEditor {
    edits: Vec<AttributeEdit>,
}

impl AttributeEditor {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Queue adding an attribute.
    pub fn add(&mut self, target: impl Into<String>, attr_type: impl Into<String>, blob: Vec<u8>) {
        self.edits.push(AttributeEdit::Add {
            target: target.into(),
            attr_type: attr_type.into(),
            blob,
        });
    }

    /// Queue removing an attribute.
    pub fn remove(&mut self, target: impl Into<String>, attr_type: impl Into<String>) {
        self.edits.push(AttributeEdit::Remove {
            target: target.into(),
            attr_type: attr_type.into(),
        });
    }

    /// Queue replacing an attribute.
    pub fn replace(
        &mut self,
        target: impl Into<String>,
        old_type: impl Into<String>,
        new_type: impl Into<String>,
        new_blob: Vec<u8>,
    ) {
        self.edits.push(AttributeEdit::Replace {
            target: target.into(),
            old_type: old_type.into(),
            new_type: new_type.into(),
            new_blob,
        });
    }

    /// Number of queued edits.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.edits.len()
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.edits.is_empty()
    }

    /// Clear the edit queue.
    pub fn clear(&mut self) {
        self.edits.clear();
    }

    /// Return all edits for a target.
    #[must_use]
    pub fn edits_for_target(&self, target: &str) -> Vec<&AttributeEdit> {
        self.edits.iter().filter(|e| match e {
            AttributeEdit::Add { target: t, .. }
            | AttributeEdit::Remove { target: t, .. }
            | AttributeEdit::Replace { target: t, .. } => t == target,
        }).collect()
    }
}

// ─── ResourcePatcher ──────────────────────────────────────────────────────────

/// A managed resource to be patched in the assembly.
#[derive(Debug, Clone)]
pub struct ResourcePatch {
    /// Name of the resource to patch.
    pub resource_name: String,
    /// New data to replace the resource content with.
    pub new_data: Vec<u8>,
    /// Whether to create the resource if it does not exist.
    pub create_if_absent: bool,
}

/// Manages patches for embedded resources.
#[derive(Debug, Default)]
pub struct ResourcePatcher {
    patches: HashMap<String, ResourcePatch>,
}

impl ResourcePatcher {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Queue a resource patch.
    pub fn patch(
        &mut self,
        resource_name: impl Into<String>,
        new_data: Vec<u8>,
        create_if_absent: bool,
    ) {
        let name = resource_name.into();
        self.patches.insert(name.clone(), ResourcePatch {
            resource_name: name,
            new_data,
            create_if_absent,
        });
    }

    /// Remove a queued patch.
    pub fn remove_patch(&mut self, resource_name: &str) -> Option<ResourcePatch> {
        self.patches.remove(resource_name)
    }

    /// Get the patch for a resource, if any.
    #[must_use]
    pub fn get_patch(&self, resource_name: &str) -> Option<&ResourcePatch> {
        self.patches.get(resource_name)
    }

    /// Number of queued patches.
    #[must_use]
    pub fn len(&self) -> usize {
        self.patches.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.patches.is_empty()
    }
}

// ─── TypeForwarder ────────────────────────────────────────────────────────────

/// A type forwarder redirects type resolution from one assembly to another.
#[derive(Debug, Clone)]
pub struct TypeForwarder {
    /// Fully-qualified type name to forward.
    pub type_name: String,
    /// The target assembly that actually defines the type.
    pub target_assembly: String,
    /// Whether forwarding is for a nested type.
    pub is_nested: bool,
}

impl TypeForwarder {
    #[must_use]
    pub fn new(type_name: impl Into<String>, target_assembly: impl Into<String>) -> Self {
        Self {
            type_name: type_name.into(),
            target_assembly: target_assembly.into(),
            is_nested: false,
        }
    }
}

// ─── IlEditorExtended ────────────────────────────────────────────────────────

/// Extended IL editor that manages patch sets, redirections, injections,
/// attribute edits, resource patches, and type forwarders.
#[derive(Debug, Default)]
pub struct IlEditorExtended {
    /// Raw byte-level patch set.
    pub patch_set: PatchSet,
    /// Method redirections.
    pub method_redirections: Vec<MethodRedirection>,
    /// Field injectors queued for application.
    pub field_injectors: Vec<FieldInjector>,
    /// Class injectors queued for application.
    pub class_injectors: Vec<ClassInjector>,
    /// Attribute editor.
    pub attribute_editor: AttributeEditor,
    /// Resource patcher.
    pub resource_patcher: ResourcePatcher,
    /// Type forwarders keyed by type name.
    pub type_forwarders: HashMap<String, TypeForwarder>,
}

impl IlEditorExtended {
    /// Create a new, empty `IlEditorExtended`.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    // ── Raw patching ───────────────────────────────────────────────────────────

    /// Add a raw byte patch.
    pub fn add_raw_patch(&mut self, entry: PatchEntry) -> Result<()> {
        self.patch_set.add(entry)
    }

    /// Apply all raw patches to a buffer.
    pub fn apply_patches(&self, buffer: &mut Vec<u8>) -> usize {
        self.patch_set.apply_to(buffer)
    }

    /// Revert all raw patches from a buffer.
    pub fn revert_patches(&self, buffer: &mut Vec<u8>) -> usize {
        self.patch_set.revert_from(buffer)
    }

    // ── Method redirections ────────────────────────────────────────────────────

    /// Register a method redirection.
    pub fn add_redirection(&mut self, redir: MethodRedirection) {
        self.method_redirections.push(redir);
    }

    /// Find all redirections for a source method.
    #[must_use]
    pub fn redirections_for(&self, type_name: &str, method_name: &str) -> Vec<&MethodRedirection> {
        self.method_redirections.iter()
            .filter(|r| r.source_type == type_name && r.source_method == method_name)
            .collect()
    }

    /// Mark all redirections for a source method as applied.
    pub fn mark_redirections_applied(&mut self, type_name: &str, method_name: &str) {
        for r in &mut self.method_redirections {
            if r.source_type == type_name && r.source_method == method_name {
                r.applied = true;
            }
        }
    }

    // ── Field injection ────────────────────────────────────────────────────────

    /// Queue a field injection.
    pub fn inject_field(&mut self, injector: FieldInjector) {
        self.field_injectors.push(injector);
    }

    /// Return all field injectors for a given type.
    #[must_use]
    pub fn field_injectors_for(&self, type_name: &str) -> Vec<&FieldInjector> {
        self.field_injectors.iter().filter(|i| i.target_type == type_name).collect()
    }

    // ── Class injection ────────────────────────────────────────────────────────

    /// Queue a class injection.
    pub fn inject_class(&mut self, injector: ClassInjector) {
        self.class_injectors.push(injector);
    }

    /// Find a class injector by full name.
    #[must_use]
    pub fn find_class_injector(&self, full_name: &str) -> Option<&ClassInjector> {
        self.class_injectors.iter().find(|c| c.full_name() == full_name)
    }

    // ── Attribute editing ──────────────────────────────────────────────────────

    /// Queue adding an attribute to a target.
    pub fn add_attribute(&mut self, target: impl Into<String>, attr_type: impl Into<String>, blob: Vec<u8>) {
        self.attribute_editor.add(target, attr_type, blob);
    }

    /// Queue removing an attribute from a target.
    pub fn remove_attribute(&mut self, target: impl Into<String>, attr_type: impl Into<String>) {
        self.attribute_editor.remove(target, attr_type);
    }

    // ── Resource patching ──────────────────────────────────────────────────────

    /// Queue a resource data replacement.
    pub fn patch_resource(&mut self, name: impl Into<String>, data: Vec<u8>) {
        self.resource_patcher.patch(name, data, false);
    }

    // ── Type forwarding ────────────────────────────────────────────────────────

    /// Add a type forwarder.
    pub fn add_type_forwarder(&mut self, forwarder: TypeForwarder) -> Result<()> {
        if self.type_forwarders.contains_key(&forwarder.type_name) {
            return Err(ExtendedEditError::ForwarderExists(forwarder.type_name));
        }
        self.type_forwarders.insert(forwarder.type_name.clone(), forwarder);
        Ok(())
    }

    /// Remove a type forwarder.
    pub fn remove_type_forwarder(&mut self, type_name: &str) -> Option<TypeForwarder> {
        self.type_forwarders.remove(type_name)
    }

    // ── Summary ────────────────────────────────────────────────────────────────

    /// Return a text summary of all pending edits.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "IlEditorExtended {{ patches={}, redirections={}, field_injectors={}, \
             class_injectors={}, attribute_edits={}, resource_patches={}, type_forwarders={} }}",
            self.patch_set.len(),
            self.method_redirections.len(),
            self.field_injectors.len(),
            self.class_injectors.len(),
            self.attribute_editor.len(),
            self.resource_patcher.len(),
            self.type_forwarders.len(),
        )
    }

    /// Returns `true` if there are any pending edits of any kind.
    #[must_use]
    pub fn has_pending_edits(&self) -> bool {
        !self.patch_set.is_empty()
            || !self.method_redirections.is_empty()
            || !self.field_injectors.is_empty()
            || !self.class_injectors.is_empty()
            || !self.attribute_editor.is_empty()
            || !self.resource_patcher.is_empty()
            || !self.type_forwarders.is_empty()
    }

    /// Clear all pending edits.
    pub fn clear_all(&mut self) {
        self.patch_set.clear();
        self.method_redirections.clear();
        self.field_injectors.clear();
        self.class_injectors.clear();
        self.attribute_editor.clear();
        self.resource_patcher = ResourcePatcher::new();
        self.type_forwarders.clear();
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── PatchEntry ────────────────────────────────────────────────────────────

    #[test]
    fn patch_entry_has_changes() {
        let e = PatchEntry::new(0, vec![0x90, 0x90], vec![0xCC, 0xCC], "breakpoint");
        assert!(e.has_changes());
    }

    #[test]
    fn patch_entry_no_changes() {
        let e = PatchEntry::new(0, vec![0xCC], vec![0xCC], "identity");
        assert!(!e.has_changes());
    }

    #[test]
    fn patch_entry_size() {
        let e = PatchEntry::new(0, vec![0u8; 4], vec![0xCC; 4], "x");
        assert_eq!(e.patch_size(), 4);
    }

    // ── PatchSet ──────────────────────────────────────────────────────────────

    #[test]
    fn patch_set_add_and_apply() {
        let mut ps = PatchSet::new();
        ps.add(PatchEntry::new(2, vec![0x00, 0x00], vec![0xCC, 0xCC], "int3")).unwrap();
        let mut buf = vec![0x00u8; 8];
        let applied = ps.apply_to(&mut buf);
        assert_eq!(applied, 1);
        assert_eq!(&buf[2..4], &[0xCC, 0xCC]);
    }

    #[test]
    fn patch_set_no_overlap() {
        let mut ps = PatchSet::new();
        ps.add(PatchEntry::new(0, vec![0u8; 4], vec![0xCC; 4], "a")).unwrap();
        ps.add(PatchEntry::new(4, vec![0u8; 4], vec![0xDD; 4], "b")).unwrap();
        assert_eq!(ps.len(), 2);
    }

    #[test]
    fn patch_set_overlap_error() {
        let mut ps = PatchSet::new();
        ps.add(PatchEntry::new(0, vec![0u8; 8], vec![0xCC; 8], "a")).unwrap();
        let res = ps.add(PatchEntry::new(4, vec![0u8; 4], vec![0xDD; 4], "b"));
        assert!(matches!(res, Err(ExtendedEditError::PatchConflict { offset: 4 })));
    }

    #[test]
    fn patch_set_revert() {
        let mut ps = PatchSet::new();
        ps.add(PatchEntry::new(0, vec![0x90, 0x90], vec![0xCC, 0xCC], "x")).unwrap();
        let mut buf = vec![0xCC, 0xCC, 0x00, 0x00];
        let reverted = ps.revert_from(&mut buf);
        assert_eq!(reverted, 1);
        assert_eq!(&buf[0..2], &[0x90, 0x90]);
    }

    #[test]
    fn patch_set_total_bytes() {
        let mut ps = PatchSet::new();
        ps.add(PatchEntry::new(0, vec![0u8; 4], vec![0u8; 4], "a")).unwrap();
        ps.add(PatchEntry::new(4, vec![0u8; 8], vec![0u8; 8], "b")).unwrap();
        assert_eq!(ps.total_bytes_modified(), 12);
    }

    #[test]
    fn patch_set_clear() {
        let mut ps = PatchSet::new();
        ps.add(PatchEntry::new(0, vec![], vec![], "x")).unwrap();
        ps.clear();
        assert!(ps.is_empty());
    }

    // ── MethodRedirection ─────────────────────────────────────────────────────

    #[test]
    fn method_redir_describe_call() {
        let r = MethodRedirection::new_call_redirect("A", "Foo", "B", "Bar");
        let desc = r.describe();
        assert!(desc.contains("A::Foo"));
        assert!(desc.contains("B::Bar"));
    }

    #[test]
    fn method_redir_describe_body_sub() {
        let r = MethodRedirection::new_body_substitute("A", "Foo", vec![0x2A]);
        assert!(r.describe().contains("substitute"));
    }

    #[test]
    fn method_redir_applied() {
        let mut r = MethodRedirection::new_call_redirect("A", "Foo", "B", "Bar");
        assert!(!r.applied);
        r.mark_applied();
        assert!(r.applied);
    }

    // ── FieldInjector ─────────────────────────────────────────────────────────

    #[test]
    fn field_injector_public_instance_flags() {
        let fi = FieldInjector::public_instance("MyType", "myField", 0x08);
        assert_eq!(fi.flags, 0x0006);
    }

    #[test]
    fn field_injector_public_static_flags() {
        let fi = FieldInjector::public_static("MyType", "staticField", 0x08);
        assert_eq!(fi.flags, 0x0016);
    }

    #[test]
    fn field_injector_add_attribute() {
        let mut fi = FieldInjector::public_instance("T", "f", 0x08);
        fi.add_custom_attribute("MyAttr", vec![0x01, 0x00]);
        assert_eq!(fi.custom_attributes.len(), 1);
    }

    // ── ClassInjector ─────────────────────────────────────────────────────────

    #[test]
    fn class_injector_full_name_with_ns() {
        let c = ClassInjector::public_sealed("MyNamespace", "MyClass");
        assert_eq!(c.full_name(), "MyNamespace.MyClass");
    }

    #[test]
    fn class_injector_full_name_no_ns() {
        let c = ClassInjector::public_sealed("", "MyClass");
        assert_eq!(c.full_name(), "MyClass");
    }

    #[test]
    fn class_injector_add_method() {
        let mut c = ClassInjector::public_sealed("NS", "C");
        c.add_method(InjectedMethod::void_method("Init", 0x0006));
        assert_eq!(c.methods.len(), 1);
    }

    #[test]
    fn injected_method_void_body() {
        let m = InjectedMethod::void_method("Run", 0x0016);
        assert_eq!(m.il_body, vec![0x2A]);
        assert_eq!(m.return_type_sig, vec![0x01]);
    }

    // ── AttributeEditor ───────────────────────────────────────────────────────

    #[test]
    fn attribute_editor_add_remove() {
        let mut ae = AttributeEditor::new();
        ae.add("MyType", "System.ObsoleteAttribute", vec![0x01, 0x00]);
        ae.remove("MyType", "System.ThreadStaticAttribute");
        assert_eq!(ae.len(), 2);
    }

    #[test]
    fn attribute_editor_replace() {
        let mut ae = AttributeEditor::new();
        ae.replace('T', "OldAttr", "NewAttr", vec![0x01, 0x00]);
        assert_eq!(ae.len(), 1);
    }

    #[test]
    fn attribute_editor_edits_for_target() {
        let mut ae = AttributeEditor::new();
        ae.add("TypeA", "AttrX", vec![]);
        ae.add("TypeB", "AttrY", vec![]);
        ae.add("TypeA", "AttrZ", vec![]);
        assert_eq!(ae.edits_for_target("TypeA").len(), 2);
    }

    #[test]
    fn attribute_editor_clear() {
        let mut ae = AttributeEditor::new();
        ae.add("T", "A", vec![]);
        ae.clear();
        assert!(ae.is_empty());
    }

    // ── ResourcePatcher ───────────────────────────────────────────────────────

    #[test]
    fn resource_patcher_patch_and_get() {
        let mut rp = ResourcePatcher::new();
        rp.patch("Strings.resx", b"new data".to_vec(), false);
        let p = rp.get_patch("Strings.resx").unwrap();
        assert_eq!(p.new_data, b"new data");
    }

    #[test]
    fn resource_patcher_remove() {
        let mut rp = ResourcePatcher::new();
        rp.patch("res1", vec![], false);
        let removed = rp.remove_patch("res1");
        assert!(removed.is_some());
        assert!(rp.is_empty());
    }

    // ── TypeForwarder ─────────────────────────────────────────────────────────

    #[test]
    fn type_forwarder_new() {
        let tf = TypeForwarder::new("MyNamespace.MyClass", "AnotherAssembly");
        assert_eq!(tf.type_name, "MyNamespace.MyClass");
        assert_eq!(tf.target_assembly, "AnotherAssembly");
    }

    // ── IlEditorExtended ──────────────────────────────────────────────────────

    #[test]
    fn editor_empty_has_no_pending() {
        let e = IlEditorExtended::new();
        assert!(!e.has_pending_edits());
    }

    #[test]
    fn editor_add_raw_patch() {
        let mut e = IlEditorExtended::new();
        e.add_raw_patch(PatchEntry::new(0, vec![0x90], vec![0xCC], "int3")).unwrap();
        assert!(e.has_pending_edits());
    }

    #[test]
    fn editor_apply_and_revert_patches() {
        let mut e = IlEditorExtended::new();
        e.add_raw_patch(PatchEntry::new(0, vec![0x90, 0x90], vec![0xCC, 0xCC], "x")).unwrap();
        let mut buf = vec![0x90, 0x90, 0x00];
        e.apply_patches(&mut buf);
        assert_eq!(&buf[0..2], &[0xCC, 0xCC]);
        e.revert_patches(&mut buf);
        assert_eq!(&buf[0..2], &[0x90, 0x90]);
    }

    #[test]
    fn editor_add_redirection() {
        let mut e = IlEditorExtended::new();
        e.add_redirection(MethodRedirection::new_call_redirect("A", "Foo", "B", "Bar"));
        assert_eq!(e.redirections_for("A", "Foo").len(), 1);
    }

    #[test]
    fn editor_mark_redirections_applied() {
        let mut e = IlEditorExtended::new();
        e.add_redirection(MethodRedirection::new_call_redirect("A", "Foo", "B", "Bar"));
        e.mark_redirections_applied("A", "Foo");
        assert!(e.method_redirections[0].applied);
    }

    #[test]
    fn editor_inject_field() {
        let mut e = IlEditorExtended::new();
        e.inject_field(FieldInjector::public_instance("MyType", "injectedField", 0x08));
        assert_eq!(e.field_injectors_for("MyType").len(), 1);
    }

    #[test]
    fn editor_inject_class() {
        let mut e = IlEditorExtended::new();
        e.inject_class(ClassInjector::public_sealed("NS", "Helper"));
        assert!(e.find_class_injector("NS.Helper").is_some());
    }

    #[test]
    fn editor_add_attribute() {
        let mut e = IlEditorExtended::new();
        e.add_attribute("MyType", "MyAttr", vec![0x01, 0x00]);
        assert!(!e.attribute_editor.is_empty());
    }

    #[test]
    fn editor_remove_attribute() {
        let mut e = IlEditorExtended::new();
        e.remove_attribute("MyType", "OldAttr");
        assert_eq!(e.attribute_editor.len(), 1);
    }

    #[test]
    fn editor_patch_resource() {
        let mut e = IlEditorExtended::new();
        e.patch_resource("MyResource.resx", b"hello".to_vec());
        assert_eq!(e.resource_patcher.len(), 1);
    }

    #[test]
    fn editor_add_type_forwarder() {
        let mut e = IlEditorExtended::new();
        e.add_type_forwarder(TypeForwarder::new("NS.T", "OtherAssembly")).unwrap();
        assert!(e.type_forwarders.contains_key("NS.T"));
    }

    #[test]
    fn editor_duplicate_forwarder_error() {
        let mut e = IlEditorExtended::new();
        e.add_type_forwarder(TypeForwarder::new("NS.T", "A")).unwrap();
        let res = e.add_type_forwarder(TypeForwarder::new("NS.T", "B"));
        assert!(matches!(res, Err(ExtendedEditError::ForwarderExists(_))));
    }

    #[test]
    fn editor_remove_type_forwarder() {
        let mut e = IlEditorExtended::new();
        e.add_type_forwarder(TypeForwarder::new("NS.T", "A")).unwrap();
        assert!(e.remove_type_forwarder("NS.T").is_some());
        assert!(!e.type_forwarders.contains_key("NS.T"));
    }

    #[test]
    fn editor_summary_text() {
        let mut e = IlEditorExtended::new();
        e.add_redirection(MethodRedirection::new_call_redirect("A", "F", "B", "G"));
        let s = e.summary();
        assert!(s.contains("redirections=1"));
    }

    #[test]
    fn editor_clear_all() {
        let mut e = IlEditorExtended::new();
        e.add_raw_patch(PatchEntry::new(0, vec![], vec![], "x")).unwrap();
        e.add_redirection(MethodRedirection::new_call_redirect("A", "F", "B", "G"));
        e.clear_all();
        assert!(!e.has_pending_edits());
    }
}
