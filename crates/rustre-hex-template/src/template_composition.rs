//! `template_composition` — Template includes, inheritance, mixins, and versioning.
//!
//! Allows templates to:
//! - `include` other templates (like `#include`), importing their structs
//! - `extends` a base template, overriding individual fields
//! - mix in reusable field sets via `mixin`
//! - conditionally include fields based on a version constraint

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────────────────────
// CompositionError
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum CompositionError {
    #[error("template '{0}' not found in registry")]
    TemplateNotFound(String),
    #[error("circular include detected: {0}")]
    CircularInclude(String),
    #[error("field '{field}' not found in base template '{base}'")]
    FieldNotFound { field: String, base: String },
    #[error("mixin '{0}' not found")]
    MixinNotFound(String),
    #[error("version constraint: {0}")]
    Version(String),
    #[error("max composition depth exceeded")]
    DepthLimit,
}

// ─────────────────────────────────────────────────────────────────────────────
// ComposedField
// ─────────────────────────────────────────────────────────────────────────────

/// A field in a composed template (after all includes/overrides resolved).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComposedField {
    pub name: String,
    pub type_name: String,
    pub comment: String,
    pub offset_hint: Option<usize>,
    pub size_hint: Option<usize>,
    /// Version at which this field was introduced (`None` = always present).
    pub since_version: Option<u32>,
    /// Version at which this field was removed.
    pub until_version: Option<u32>,
    pub is_array: bool,
    pub array_count_expr: Option<String>,
    /// Whether this field was inherited from a base template.
    pub inherited: bool,
    /// Source template id.
    pub source_template: Option<String>,
    /// Condition expression (evaluated at parse time).
    pub condition: Option<String>,
    /// Padding/alignment bytes before this field.
    pub pre_padding: usize,
}

impl ComposedField {
    /// Returns `true` if this field should be included for a given version.
    #[must_use]
    pub fn active_for_version(&self, version: u32) -> bool {
        let since_ok = self.since_version.map_or(true, |v| version >= v);
        let until_ok = self.until_version.map_or(true, |v| version < v);
        since_ok && until_ok
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ComposedStruct
// ─────────────────────────────────────────────────────────────────────────────

/// A struct definition after composition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComposedStruct {
    pub name: String,
    pub fields: Vec<ComposedField>,
    pub comment: String,
    /// Total minimum size (sum of size_hint for non-optional fields).
    pub min_size: usize,
}

impl ComposedStruct {
    /// Fields active for `version`.
    #[must_use]
    pub fn active_fields(&self, version: u32) -> Vec<&ComposedField> {
        self.fields.iter().filter(|f| f.active_for_version(version)).collect()
    }

    /// Compute minimum size for a given version.
    #[must_use]
    pub fn size_for_version(&self, version: u32) -> usize {
        self.active_fields(version)
            .iter()
            .map(|f| f.size_hint.unwrap_or(0) + f.pre_padding)
            .sum()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// FieldOverride
// ─────────────────────────────────────────────────────────────────────────────

/// An override applied to an inherited field.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldOverride {
    pub field_name: String,
    pub new_type: Option<String>,
    pub new_comment: Option<String>,
    pub new_condition: Option<String>,
    pub new_since_version: Option<u32>,
    pub new_until_version: Option<u32>,
}

// ─────────────────────────────────────────────────────────────────────────────
// TemplateDefinition (raw, before composition)
// ─────────────────────────────────────────────────────────────────────────────

/// A raw template definition (as authored, before includes are resolved).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateDefinition {
    pub id: String,
    pub name: String,
    pub description: String,
    /// Templates to include (their structs are imported into this template's namespace).
    pub includes: Vec<String>,
    /// Base template to extend (fields are inherited and can be overridden).
    pub extends: Option<String>,
    /// Mixins to apply (fields are prepended/appended to the root struct).
    pub mixins: Vec<MixinApplication>,
    /// Field overrides (only valid when `extends` is set).
    pub overrides: Vec<FieldOverride>,
    /// Structs defined in this template.
    pub structs: Vec<RawStruct>,
    /// Version number of this template definition.
    pub version: u32,
}

/// A mixin application: which mixin, and where to insert it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MixinApplication {
    pub mixin_id: String,
    pub position: MixinPosition,
    /// Insert into this struct (default: root struct).
    pub target_struct: Option<String>,
}

/// Where in the struct to insert mixin fields.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum MixinPosition {
    Prepend,
    Append,
    /// Insert before the named field.
    Before(String),
    /// Insert after the named field.
    After(String),
}

// ─────────────────────────────────────────────────────────────────────────────
// RawStruct / RawField
// ─────────────────────────────────────────────────────────────────────────────

/// A struct in a raw (unresolved) template.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawStruct {
    pub name: String,
    pub fields: Vec<RawField>,
    pub comment: String,
}

/// A field in a raw struct.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawField {
    pub name: String,
    pub type_name: String,
    pub comment: String,
    pub size_hint: Option<usize>,
    pub since_version: Option<u32>,
    pub until_version: Option<u32>,
    pub is_array: bool,
    pub array_count_expr: Option<String>,
    pub condition: Option<String>,
    pub alignment: Option<usize>,
}

impl RawField {
    fn to_composed(&self, inherited: bool, source: Option<String>) -> ComposedField {
        ComposedField {
            name: self.name.clone(),
            type_name: self.type_name.clone(),
            comment: self.comment.clone(),
            offset_hint: None,
            size_hint: self.size_hint,
            since_version: self.since_version,
            until_version: self.until_version,
            is_array: self.is_array,
            array_count_expr: self.array_count_expr.clone(),
            inherited,
            source_template: source,
            condition: self.condition.clone(),
            pre_padding: 0,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Mixin
// ─────────────────────────────────────────────────────────────────────────────

/// A reusable field set that can be mixed into multiple structs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Mixin {
    pub id: String,
    pub name: String,
    pub fields: Vec<RawField>,
    pub description: String,
}

// ─────────────────────────────────────────────────────────────────────────────
// TemplateRegistry
// ─────────────────────────────────────────────────────────────────────────────

/// Registry that stores raw templates and mixins and resolves compositions.
#[derive(Debug, Default)]
pub struct TemplateRegistry {
    templates: HashMap<String, TemplateDefinition>,
    mixins: HashMap<String, Mixin>,
}

impl TemplateRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a template definition.
    pub fn register_template(&mut self, def: TemplateDefinition) {
        self.templates.insert(def.id.clone(), def);
    }

    /// Register a mixin.
    pub fn register_mixin(&mut self, mixin: Mixin) {
        self.mixins.insert(mixin.id.clone(), mixin);
    }

    #[must_use]
    pub fn get_template(&self, id: &str) -> Option<&TemplateDefinition> {
        self.templates.get(id)
    }

    #[must_use]
    pub fn get_mixin(&self, id: &str) -> Option<&Mixin> {
        self.mixins.get(id)
    }

    /// Compose a template by resolving all includes, extends, and mixins.
    pub fn compose(
        &self,
        template_id: &str,
    ) -> Result<ComposedTemplate, CompositionError> {
        let mut visited = vec![];
        self.compose_inner(template_id, &mut visited, 0)
    }

    fn compose_inner(
        &self,
        template_id: &str,
        visited: &mut Vec<String>,
        depth: usize,
    ) -> Result<ComposedTemplate, CompositionError> {
        if depth > 32 {
            return Err(CompositionError::DepthLimit);
        }
        if visited.contains(&template_id.to_string()) {
            return Err(CompositionError::CircularInclude(template_id.to_string()));
        }

        let def = self
            .templates
            .get(template_id)
            .ok_or_else(|| CompositionError::TemplateNotFound(template_id.to_string()))?;

        visited.push(template_id.to_string());

        // Start with base template if this one extends something
        let mut composed = if let Some(ref base_id) = def.extends {
            let mut base = self.compose_inner(base_id, visited, depth + 1)?;
            base.derived_from = Some(base_id.clone());
            base
        } else {
            ComposedTemplate {
                id: template_id.to_string(),
                name: def.name.clone(),
                description: def.description.clone(),
                structs: HashMap::new(),
                root_struct: None,
                derived_from: None,
                version: def.version,
                included_templates: vec![],
            }
        };

        composed.id = template_id.to_string();
        composed.name = def.name.clone();
        composed.description = def.description.clone();
        composed.version = def.version;

        // Process includes
        for inc_id in &def.includes {
            let inc = self.compose_inner(inc_id, visited, depth + 1)?;
            composed.included_templates.push(inc_id.clone());
            for (name, st) in inc.structs {
                composed.structs.entry(name).or_insert(st);
            }
        }

        // Add/override structs from this template
        for raw_st in &def.structs {
            if let Some(existing) = composed.structs.get_mut(&raw_st.name) {
                // Override: merge fields from the raw struct into the existing one
                for raw_field in &raw_st.fields {
                    let cf = raw_field.to_composed(false, Some(template_id.to_string()));
                    if let Some(pos) = existing.fields.iter().position(|f| f.name == cf.name) {
                        existing.fields[pos] = cf;
                    } else {
                        existing.fields.push(cf);
                    }
                }
            } else {
                let cs = ComposedStruct {
                    name: raw_st.name.clone(),
                    fields: raw_st
                        .fields
                        .iter()
                        .map(|f| f.to_composed(false, Some(template_id.to_string())))
                        .collect(),
                    comment: raw_st.comment.clone(),
                    min_size: 0,
                };
                composed.structs.insert(raw_st.name.clone(), cs);
            }
        }

        // Apply field overrides
        for ov in &def.overrides {
            let base_name = def.extends.as_deref().unwrap_or(template_id);
            let mut found = false;
            for st in composed.structs.values_mut() {
                if let Some(field) = st.fields.iter_mut().find(|f| f.name == ov.field_name) {
                    if let Some(ref nt) = ov.new_type {
                        field.type_name = nt.clone();
                    }
                    if let Some(ref nc) = ov.new_comment {
                        field.comment = nc.clone();
                    }
                    if let Some(ref ncond) = ov.new_condition {
                        field.condition = Some(ncond.clone());
                    }
                    if let Some(sv) = ov.new_since_version {
                        field.since_version = Some(sv);
                    }
                    if let Some(uv) = ov.new_until_version {
                        field.until_version = Some(uv);
                    }
                    found = true;
                }
            }
            if !found {
                return Err(CompositionError::FieldNotFound {
                    field: ov.field_name.clone(),
                    base: base_name.to_string(),
                });
            }
        }

        // Apply mixins
        for mixin_app in &def.mixins {
            let mixin = self
                .mixins
                .get(&mixin_app.mixin_id)
                .ok_or_else(|| CompositionError::MixinNotFound(mixin_app.mixin_id.clone()))?;

            let target_name = mixin_app
                .target_struct
                .clone()
                .or_else(|| composed.root_struct.clone())
                .or_else(|| composed.structs.keys().next().cloned());

            if let Some(tn) = target_name {
                let mixin_fields: Vec<ComposedField> = mixin
                    .fields
                    .iter()
                    .map(|f| f.to_composed(false, Some(mixin_app.mixin_id.clone())))
                    .collect();

                let st = composed.structs.entry(tn.clone()).or_insert_with(|| ComposedStruct {
                    name: tn.clone(),
                    fields: vec![],
                    comment: String::new(),
                    min_size: 0,
                });

                match &mixin_app.position {
                    MixinPosition::Prepend => {
                        let existing = std::mem::take(&mut st.fields);
                        st.fields = mixin_fields;
                        st.fields.extend(existing);
                    }
                    MixinPosition::Append => {
                        st.fields.extend(mixin_fields);
                    }
                    MixinPosition::Before(field_name) => {
                        let pos = st.fields.iter().position(|f| &f.name == field_name).unwrap_or(0);
                        for (i, mf) in mixin_fields.into_iter().enumerate() {
                            st.fields.insert(pos + i, mf);
                        }
                    }
                    MixinPosition::After(field_name) => {
                        let pos = st.fields.iter().position(|f| &f.name == field_name)
                            .map(|p| p + 1)
                            .unwrap_or(st.fields.len());
                        for (i, mf) in mixin_fields.into_iter().enumerate() {
                            st.fields.insert(pos + i, mf);
                        }
                    }
                }
            }
        }

        // Set root struct (first struct defined, or explicitly named)
        if composed.root_struct.is_none() && !composed.structs.is_empty() {
            composed.root_struct = Some(def.structs.first().map(|s| s.name.clone())
                .unwrap_or_else(|| composed.structs.keys().next().cloned().unwrap()));
        }

        // Compute min sizes
        for st in composed.structs.values_mut() {
            st.min_size = st.fields.iter().map(|f| f.size_hint.unwrap_or(0)).sum();
        }

        visited.pop();
        Ok(composed)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ComposedTemplate
// ─────────────────────────────────────────────────────────────────────────────

/// A fully composed template ready for use.
#[derive(Debug, Clone)]
pub struct ComposedTemplate {
    pub id: String,
    pub name: String,
    pub description: String,
    pub structs: HashMap<String, ComposedStruct>,
    pub root_struct: Option<String>,
    pub derived_from: Option<String>,
    pub version: u32,
    pub included_templates: Vec<String>,
}

impl ComposedTemplate {
    /// Get the root struct.
    #[must_use]
    pub fn root(&self) -> Option<&ComposedStruct> {
        self.root_struct.as_deref().and_then(|n| self.structs.get(n))
    }

    /// Get fields of the root struct active for `version`.
    #[must_use]
    pub fn root_fields_for_version(&self, version: u32) -> Vec<&ComposedField> {
        self.root()
            .map(|s| s.active_fields(version))
            .unwrap_or_default()
    }

    /// Summary for display.
    #[must_use]
    pub fn summary(&self) -> String {
        let struct_count = self.structs.len();
        let total_fields: usize = self.structs.values().map(|s| s.fields.len()).sum();
        format!(
            "{} (v{}) — {struct_count} struct(s), {total_fields} field(s)",
            self.name, self.version
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Builder helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Fluent builder for a `TemplateDefinition`.
pub struct TemplateBuilder {
    def: TemplateDefinition,
}

impl TemplateBuilder {
    pub fn new(id: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            def: TemplateDefinition {
                id: id.into(),
                name: name.into(),
                description: String::new(),
                includes: vec![],
                extends: None,
                mixins: vec![],
                overrides: vec![],
                structs: vec![],
                version: 1,
            },
        }
    }

    pub fn description(mut self, d: impl Into<String>) -> Self {
        self.def.description = d.into();
        self
    }

    pub fn extends(mut self, base: impl Into<String>) -> Self {
        self.def.extends = Some(base.into());
        self
    }

    pub fn include(mut self, template_id: impl Into<String>) -> Self {
        self.def.includes.push(template_id.into());
        self
    }

    #[must_use]
    pub const fn version(mut self, v: u32) -> Self {
        self.def.version = v;
        self
    }

    #[must_use]
    pub fn add_struct(mut self, st: RawStruct) -> Self {
        self.def.structs.push(st);
        self
    }

    #[must_use]
    pub fn override_field(mut self, ov: FieldOverride) -> Self {
        self.def.overrides.push(ov);
        self
    }

    pub fn add_mixin(mut self, mixin_id: impl Into<String>, pos: MixinPosition) -> Self {
        self.def.mixins.push(MixinApplication {
            mixin_id: mixin_id.into(),
            position: pos,
            target_struct: None,
        });
        self
    }

    #[must_use]
    pub fn build(self) -> TemplateDefinition {
        self.def
    }
}

/// Fluent builder for a `RawStruct`.
pub struct StructBuilder {
    st: RawStruct,
}

impl StructBuilder {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            st: RawStruct {
                name: name.into(),
                fields: vec![],
                comment: String::new(),
            },
        }
    }

    pub fn comment(mut self, c: impl Into<String>) -> Self {
        self.st.comment = c.into();
        self
    }

    pub fn field(
        mut self,
        name: impl Into<String>,
        type_name: impl Into<String>,
        size: Option<usize>,
    ) -> Self {
        self.st.fields.push(RawField {
            name: name.into(),
            type_name: type_name.into(),
            comment: String::new(),
            size_hint: size,
            since_version: None,
            until_version: None,
            is_array: false,
            array_count_expr: None,
            condition: None,
            alignment: None,
        });
        self
    }

    pub fn versioned_field(
        mut self,
        name: impl Into<String>,
        type_name: impl Into<String>,
        size: Option<usize>,
        since: Option<u32>,
        until: Option<u32>,
    ) -> Self {
        self.st.fields.push(RawField {
            name: name.into(),
            type_name: type_name.into(),
            comment: String::new(),
            size_hint: size,
            since_version: since,
            until_version: until,
            is_array: false,
            array_count_expr: None,
            condition: None,
            alignment: None,
        });
        self
    }

    #[must_use]
    pub fn build(self) -> RawStruct {
        self.st
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_registry() -> TemplateRegistry {
        let mut reg = TemplateRegistry::new();

        // Base template
        let base = TemplateBuilder::new("base", "Base Header")
            .version(1)
            .add_struct(
                StructBuilder::new("Header")
                    .field("magic", "u32", Some(4))
                    .field("version", "u16", Some(2))
                    .field("size", "u32", Some(4))
                    .build(),
            )
            .build();
        reg.register_template(base);

        // Extended template
        let ext = TemplateBuilder::new("extended", "Extended Header")
            .version(2)
            .extends("base")
            .add_struct(
                StructBuilder::new("Header")
                    .versioned_field("flags", "u32", Some(4), Some(2), None)
                    .build(),
            )
            .build();
        reg.register_template(ext);

        // Mixin
        let mixin = Mixin {
            id: "checksum_mixin".to_string(),
            name: "Checksum fields".to_string(),
            fields: vec![RawField {
                name: "crc32".to_string(),
                type_name: "u32".to_string(),
                comment: "CRC32 checksum".to_string(),
                size_hint: Some(4),
                since_version: None,
                until_version: None,
                is_array: false,
                array_count_expr: None,
                condition: None,
                alignment: None,
            }],
            description: "Adds CRC32 field".to_string(),
        };
        reg.register_mixin(mixin);

        // Template with mixin
        let with_mixin = TemplateBuilder::new("with_checksum", "Header with Checksum")
            .extends("base")
            .add_mixin("checksum_mixin", MixinPosition::Append)
            .build();
        reg.register_template(with_mixin);

        reg
    }

    #[test]
    fn compose_base() {
        let reg = make_registry();
        let ct = reg.compose("base").unwrap();
        assert_eq!(ct.id, "base");
        let root = ct.root().unwrap();
        assert_eq!(root.fields.len(), 3);
    }

    #[test]
    fn compose_extended_inherits_fields() {
        let reg = make_registry();
        let ct = reg.compose("extended").unwrap();
        let root = ct.root().unwrap();
        // Should have base fields + the new versioned field
        assert!(root.fields.iter().any(|f| f.name == "magic"));
        assert!(root.fields.iter().any(|f| f.name == "flags"));
    }

    #[test]
    fn versioned_field_filtering() {
        let reg = make_registry();
        let ct = reg.compose("extended").unwrap();
        let root = ct.root().unwrap();

        // v1: flags not active (since version 2)
        let v1 = root.active_fields(1);
        assert!(!v1.iter().any(|f| f.name == "flags"));

        // v2: flags active
        let v2 = root.active_fields(2);
        assert!(v2.iter().any(|f| f.name == "flags"));
    }

    #[test]
    fn mixin_appended() {
        let reg = make_registry();
        let ct = reg.compose("with_checksum").unwrap();
        let root = ct.root().unwrap();
        let last = root.fields.last().unwrap();
        assert_eq!(last.name, "crc32");
    }

    #[test]
    fn circular_include_detected() {
        let mut reg = TemplateRegistry::new();
        let a = TemplateBuilder::new("a", "A").include("b").build();
        let b = TemplateBuilder::new("b", "B").include("a").build();
        reg.register_template(a);
        reg.register_template(b);
        assert!(matches!(reg.compose("a"), Err(CompositionError::CircularInclude(_))));
    }

    #[test]
    fn template_not_found() {
        let reg = TemplateRegistry::new();
        assert!(matches!(
            reg.compose("nonexistent"),
            Err(CompositionError::TemplateNotFound(_))
        ));
    }
}
