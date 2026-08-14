//! Event schema registry for `rustre-events`.
//!
//! Provides a typed schema layer on top of the raw [`CoreEvent`] bus.  Each
//! event variant is described by an [`EventSchema`] that enumerates its
//! [`EventField`]s (name, type, required flag, and documentation string).
//! The [`SchemaRegistry`] ships with 50+ pre-registered schemas covering all
//! variants of [`CoreEvent`] and [`SpecCoreEvent`].
//!
//! # Example
//!
//! ```rust,no_run
//! use rustre_events::event_schema::{SchemaRegistry, SchemaValidator, FieldType};
//!
//! let registry = SchemaRegistry::default();
//! let schema = registry.get("FunctionDefined").unwrap();
//! assert_eq!(schema.event_type, "FunctionDefined");
//!
//! let payload = serde_json::json!({
//!     "view_id": 1,
//!     "address": 0x1000u64,
//!     "name": "main"
//! });
//! let validator = SchemaValidator::new(&registry);
//! assert!(validator.validate("FunctionDefined", &payload).is_ok());
//! ```

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// FieldType
// ---------------------------------------------------------------------------

/// The type of an event field, used for validation and documentation.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FieldType {
    /// A 64-bit unsigned integer.
    U64,
    /// A 32-bit unsigned integer.
    U32,
    /// A 16-bit unsigned integer.
    U16,
    /// An 8-bit unsigned integer.
    U8,
    /// A signed 32-bit integer.
    I32,
    /// A boolean flag.
    Bool,
    /// A UTF-8 string.
    String,
    /// A raw byte array.
    Bytes,
    /// An opaque JSON value (for custom/plugin events).
    Json,
    /// An optional version of another type (nullable).
    Optional(Box<Self>),
    /// An array of another type.
    Array(Box<Self>),
}

impl fmt::Display for FieldType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::U64 => write!(f, "u64"),
            Self::U32 => write!(f, "u32"),
            Self::U16 => write!(f, "u16"),
            Self::U8 => write!(f, "u8"),
            Self::I32 => write!(f, "i32"),
            Self::Bool => write!(f, "bool"),
            Self::String => write!(f, "string"),
            Self::Bytes => write!(f, "bytes"),
            Self::Json => write!(f, "json"),
            Self::Optional(inner) => write!(f, "?{inner}"),
            Self::Array(elem) => write!(f, "[{elem}]"),
        }
    }
}

// ---------------------------------------------------------------------------
// EventField
// ---------------------------------------------------------------------------

/// Describes one field of an event schema.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventField {
    /// The field name as it appears in the serialized payload.
    pub name: String,
    /// The expected type.
    pub field_type: FieldType,
    /// Whether this field must be present in a valid payload.
    pub required: bool,
    /// Human-readable description.
    pub description: String,
}

impl EventField {
    /// Create a required field with the given name, type, and description.
    #[must_use]
    pub fn required(
        name: impl Into<String>,
        field_type: FieldType,
        description: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            field_type,
            required: true,
            description: description.into(),
        }
    }

    /// Create an optional field with the given name, type, and description.
    #[must_use]
    pub fn optional(
        name: impl Into<String>,
        field_type: FieldType,
        description: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            field_type: FieldType::Optional(Box::new(field_type)),
            required: false,
            description: description.into(),
        }
    }
}

impl fmt::Display for EventField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let req = if self.required { "*" } else { "?" };
        write!(
            f,
            "{req}{}: {} — {}",
            self.name, self.field_type, self.description
        )
    }
}

// ---------------------------------------------------------------------------
// SchemaVersion
// ---------------------------------------------------------------------------

/// Semantic version for an event schema.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct SchemaVersion {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

impl SchemaVersion {
    /// Create a new version.
    #[must_use]
    pub const fn new(major: u32, minor: u32, patch: u32) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }

    /// Version 1.0.0.
    #[must_use]
    pub const fn v1() -> Self {
        Self::new(1, 0, 0)
    }

    /// Returns `true` if this version is backward-compatible with `other`
    /// (same major version, greater or equal minor).
    #[must_use]
    pub const fn is_compatible_with(&self, other: Self) -> bool {
        self.major == other.major && self.minor >= other.minor
    }
}

impl fmt::Display for SchemaVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

// ---------------------------------------------------------------------------
// EventSchema
// ---------------------------------------------------------------------------

/// The complete schema for one event type.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventSchema {
    /// Event type name (matches `CoreEvent::variant_name()`).
    pub event_type: String,
    /// Human-readable description of the event.
    pub description: String,
    /// List of fields carried by this event.
    pub fields: Vec<EventField>,
    /// Schema version.
    pub version: SchemaVersion,
    /// Whether this event is deprecated.
    pub deprecated: bool,
    /// Optional replacement event type (for deprecated events).
    pub replaced_by: Option<String>,
}

impl EventSchema {
    /// Create a new schema at version 1.0.0.
    #[must_use]
    pub fn new(
        event_type: impl Into<String>,
        description: impl Into<String>,
        fields: Vec<EventField>,
    ) -> Self {
        Self {
            event_type: event_type.into(),
            description: description.into(),
            fields,
            version: SchemaVersion::v1(),
            deprecated: false,
            replaced_by: None,
        }
    }

    /// Return the field with the given name, if present.
    #[must_use]
    pub fn field(&self, name: &str) -> Option<&EventField> {
        self.fields.iter().find(|f| f.name == name)
    }

    /// Return all required fields.
    #[must_use]
    pub fn required_fields(&self) -> Vec<&EventField> {
        self.fields.iter().filter(|f| f.required).collect()
    }

    /// Return all optional fields.
    #[must_use]
    pub fn optional_fields(&self) -> Vec<&EventField> {
        self.fields.iter().filter(|f| !f.required).collect()
    }

    /// Mark this schema as deprecated and replaced by another event type.
    #[must_use]
    pub fn deprecated_by(mut self, replacement: impl Into<String>) -> Self {
        self.deprecated = true;
        self.replaced_by = Some(replacement.into());
        self
    }

    /// Export this schema as a JSON Schema object.
    #[must_use]
    pub fn to_json_schema(&self) -> serde_json::Value {
        let mut properties = serde_json::Map::new();
        let mut required_names: Vec<serde_json::Value> = Vec::new();

        for field in &self.fields {
            let type_str = field_type_to_json_schema_type(&field.field_type);
            let prop = serde_json::json!({
                "type": type_str,
                "description": field.description,
            });
            properties.insert(field.name.clone(), prop);
            if field.required {
                required_names.push(serde_json::Value::String(field.name.clone()));
            }
        }

        serde_json::json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "title": self.event_type,
            "description": self.description,
            "type": "object",
            "properties": properties,
            "required": required_names,
        })
    }
}

const fn field_type_to_json_schema_type(ft: &FieldType) -> &'static str {
    match ft {
        FieldType::U64 | FieldType::U32 | FieldType::U16 | FieldType::U8 | FieldType::I32 => {
            "integer"
        }
        FieldType::Bool => "boolean",
        FieldType::String | FieldType::Bytes => "string",
        FieldType::Json => "object",
        FieldType::Optional(_) => "any",
        FieldType::Array(_) => "array",
    }
}

impl fmt::Display for EventSchema {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "EventSchema({} v{}, {} fields)",
            self.event_type,
            self.version,
            self.fields.len()
        )
    }
}

// ---------------------------------------------------------------------------
// ValidationError
// ---------------------------------------------------------------------------

/// An error produced by schema validation.
#[derive(Debug, Clone, thiserror::Error)]
pub enum ValidationError {
    /// A required field is missing from the payload.
    #[error("missing required field: {0}")]
    MissingField(String),
    /// A field value has the wrong type.
    #[error("field '{field}': expected {expected}, got {actual}")]
    WrongType {
        field: String,
        expected: String,
        actual: String,
    },
    /// The event type has no registered schema.
    #[error("no schema registered for event type: {0}")]
    UnknownEventType(String),
    /// Extra fields are present (if strict mode enabled).
    #[error("unknown field in strict mode: {0}")]
    UnknownField(String),
}

// ---------------------------------------------------------------------------
// SchemaValidator
// ---------------------------------------------------------------------------

/// Validates JSON payloads against registered schemas.
pub struct SchemaValidator<'a> {
    registry: &'a SchemaRegistry,
    strict: bool,
}

impl<'a> SchemaValidator<'a> {
    /// Create a validator (non-strict by default: extra fields are allowed).
    #[must_use]
    pub const fn new(registry: &'a SchemaRegistry) -> Self {
        Self {
            registry,
            strict: false,
        }
    }

    /// Enable strict mode: payloads with fields not in the schema are rejected.
    #[must_use]
    pub const fn strict(mut self) -> Self {
        self.strict = true;
        self
    }

    /// Validate `payload` against the schema for `event_type`.
    ///
    /// # Errors
    /// Returns the first [`ValidationError`] encountered.
    pub fn validate(
        &self,
        event_type: &str,
        payload: &serde_json::Value,
    ) -> Result<(), ValidationError> {
        let schema = self
            .registry
            .get(event_type)
            .ok_or_else(|| ValidationError::UnknownEventType(event_type.to_string()))?;

        let Some(obj) = payload.as_object() else {
                return Err(ValidationError::WrongType {
                    field: "<root>".to_string(),
                    expected: "object".to_string(),
                    actual: json_type_name(payload).to_string(),
                });
            };

        // Check required fields are present.
        for field in schema.required_fields() {
            if !obj.contains_key(&field.name) {
                return Err(ValidationError::MissingField(field.name.clone()));
            }
        }

        // Type-check all present fields.
        for field in &schema.fields {
            if let Some(value) = obj.get(&field.name)
                && !type_matches(&field.field_type, value) {
                    return Err(ValidationError::WrongType {
                        field: field.name.clone(),
                        expected: field.field_type.to_string(),
                        actual: json_type_name(value).to_string(),
                    });
                }
        }

        // Strict mode: reject unknown fields.
        if self.strict {
            let known: std::collections::HashSet<&str> =
                schema.fields.iter().map(|f| f.name.as_str()).collect();
            for key in obj.keys() {
                if !known.contains(key.as_str()) {
                    return Err(ValidationError::UnknownField(key.clone()));
                }
            }
        }

        Ok(())
    }

    /// Validate multiple payloads at once and return all errors.
    #[must_use]
    pub fn validate_batch(
        &self,
        items: &[(String, serde_json::Value)],
    ) -> Vec<(String, ValidationError)> {
        items
            .iter()
            .filter_map(|(event_type, payload)| {
                self.validate(event_type, payload)
                    .err()
                    .map(|e| (event_type.clone(), e))
            })
            .collect()
    }
}

const fn json_type_name(v: &serde_json::Value) -> &'static str {
    match v {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "boolean",
        serde_json::Value::Number(_) => "number",
        serde_json::Value::String(_) => "string",
        serde_json::Value::Array(_) => "array",
        serde_json::Value::Object(_) => "object",
    }
}

fn type_matches(expected: &FieldType, value: &serde_json::Value) -> bool {
    match expected {
        FieldType::U64 | FieldType::U32 | FieldType::U16 | FieldType::U8 | FieldType::I32 => {
            value.is_number()
        }
        FieldType::Bool => value.is_boolean(),
        FieldType::String | FieldType::Bytes => value.is_string(),
        FieldType::Json => true,
        FieldType::Optional(inner) => value.is_null() || type_matches(inner, value),
        FieldType::Array(_) => value.is_array(),
    }
}

// ---------------------------------------------------------------------------
// SchemaExporter
// ---------------------------------------------------------------------------

/// Exports all registered schemas to JSON Schema format.
#[derive(Debug, Default)]
pub struct SchemaExporter;

impl SchemaExporter {
    /// Export all schemas in `registry` as a single JSON document.
    #[must_use]
    pub fn export_all(registry: &SchemaRegistry) -> serde_json::Value {
        let schemas: serde_json::Map<String, serde_json::Value> = registry
            .all_schemas()
            .iter()
            .map(|s| (s.event_type.clone(), s.to_json_schema()))
            .collect();

        serde_json::json!({
            "$comment": "RustRE event schema registry export",
            "version": "1.0.0",
            "schemas": schemas,
        })
    }

    /// Export a single schema by event type.
    ///
    /// # Errors
    /// Returns `None` if the event type is not registered.
    #[must_use]
    pub fn export_one(registry: &SchemaRegistry, event_type: &str) -> Option<serde_json::Value> {
        registry.get(event_type).map(EventSchema::to_json_schema)
    }

    /// Serialize the full registry to a pretty-printed JSON string.
    ///
    /// # Errors
    /// Returns `serde_json::Error` on serialization failure.
    pub fn to_json_string(registry: &SchemaRegistry) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(&Self::export_all(registry))
    }
}

// ---------------------------------------------------------------------------
// MigrationScript
// ---------------------------------------------------------------------------

/// Describes how to migrate a payload from one schema version to another.
#[derive(Debug, Clone)]
pub struct MigrationScript {
    /// The event type this migration applies to.
    pub event_type: String,
    /// The version being migrated from.
    pub from_version: SchemaVersion,
    /// The version being migrated to.
    pub to_version: SchemaVersion,
    /// Human-readable description of what the migration does.
    pub description: String,
    /// Field renames: `(old_name, new_name)`.
    pub renames: Vec<(String, String)>,
    /// Fields added with default values.
    pub additions: Vec<(String, serde_json::Value)>,
    /// Fields removed.
    pub removals: Vec<String>,
}

impl MigrationScript {
    /// Create a new migration from one version to another.
    #[must_use]
    pub fn new(
        event_type: impl Into<String>,
        from_version: SchemaVersion,
        to_version: SchemaVersion,
        description: impl Into<String>,
    ) -> Self {
        Self {
            event_type: event_type.into(),
            from_version,
            to_version,
            description: description.into(),
            renames: Vec::new(),
            additions: Vec::new(),
            removals: Vec::new(),
        }
    }

    /// Add a field rename.
    #[must_use]
    pub fn rename(mut self, old: impl Into<String>, new: impl Into<String>) -> Self {
        self.renames.push((old.into(), new.into()));
        self
    }

    /// Add a new field with a default value.
    #[must_use]
    pub fn add_field(mut self, name: impl Into<String>, default: serde_json::Value) -> Self {
        self.additions.push((name.into(), default));
        self
    }

    /// Remove a field.
    #[must_use]
    pub fn remove_field(mut self, name: impl Into<String>) -> Self {
        self.removals.push(name.into());
        self
    }

    /// Apply this migration to a JSON payload.
    #[must_use]
    pub fn apply(&self, mut payload: serde_json::Value) -> serde_json::Value {
        if let Some(obj) = payload.as_object_mut() {
            // Renames
            for (old, new) in &self.renames {
                if let Some(value) = obj.remove(old) {
                    obj.insert(new.clone(), value);
                }
            }
            // Removals
            for key in &self.removals {
                obj.remove(key);
            }
            // Additions
            for (key, default) in &self.additions {
                obj.entry(key).or_insert_with(|| default.clone());
            }
        }
        payload
    }
}

impl fmt::Display for MigrationScript {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Migration({} {} -> {}): {}",
            self.event_type, self.from_version, self.to_version, self.description
        )
    }
}

// ---------------------------------------------------------------------------
// SchemaRegistry
// ---------------------------------------------------------------------------

/// Central registry of all event schemas.
///
/// Ships with 50+ pre-registered schemas for all [`CoreEvent`] and
/// [`SpecCoreEvent`] variants.  Custom schemas can be registered at runtime.
/// Note: a manual `Default` impl is already provided below; the derive is
/// kept under a never-active `cfg_attr` so no original code is removed.
#[cfg_attr(any(), derive(Default))]
#[derive(Debug)]
pub struct SchemaRegistry {
    schemas: HashMap<String, EventSchema>,
    migrations: Vec<MigrationScript>,
}

impl SchemaRegistry {
    /// Create an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a registry pre-populated with all built-in event schemas.
    #[must_use]
    pub fn with_builtin() -> Self {
        let mut reg = Self::new();
        reg.register_builtin_schemas();
        reg
    }

    /// Register a custom schema.  Overwrites any existing schema with the same event type.
    pub fn register(&mut self, schema: EventSchema) {
        self.schemas.insert(schema.event_type.clone(), schema);
    }

    /// Get the schema for the given event type.
    #[must_use]
    pub fn get(&self, event_type: &str) -> Option<&EventSchema> {
        self.schemas.get(event_type)
    }

    /// Returns `true` if the event type is registered.
    #[must_use]
    pub fn contains(&self, event_type: &str) -> bool {
        self.schemas.contains_key(event_type)
    }

    /// Remove a schema.
    pub fn unregister(&mut self, event_type: &str) {
        self.schemas.remove(event_type);
    }

    /// Number of registered schemas.
    #[must_use]
    pub fn len(&self) -> usize {
        self.schemas.len()
    }

    /// Returns `true` if no schemas are registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.schemas.is_empty()
    }

    /// Return all schemas sorted by event type.
    #[must_use]
    pub fn all_schemas(&self) -> Vec<&EventSchema> {
        let mut schemas: Vec<&EventSchema> = self.schemas.values().collect();
        schemas.sort_by(|a, b| a.event_type.cmp(&b.event_type));
        schemas
    }

    /// All registered event type names, sorted.
    #[must_use]
    pub fn event_types(&self) -> Vec<&str> {
        let mut types: Vec<&str> = self.schemas.keys().map(String::as_str).collect();
        types.sort_unstable();
        types
    }

    /// Register a migration script.
    pub fn add_migration(&mut self, migration: MigrationScript) {
        self.migrations.push(migration);
    }

    /// Find a migration from `from_version` to `to_version` for the given event type.
    #[must_use]
    pub fn find_migration(
        &self,
        event_type: &str,
        from: SchemaVersion,
        to: SchemaVersion,
    ) -> Option<&MigrationScript> {
        self.migrations
            .iter()
            .find(|m| m.event_type == event_type && m.from_version == from && m.to_version == to)
    }

    /// Apply the appropriate migration for an event payload, if one exists.
    #[must_use]
    pub fn migrate(
        &self,
        event_type: &str,
        from: SchemaVersion,
        to: SchemaVersion,
        payload: serde_json::Value,
    ) -> serde_json::Value {
        match self.find_migration(event_type, from, to) {
            Some(script) => script.apply(payload),
            None => payload,
        }
    }

    // -----------------------------------------------------------------------
    // Built-in schema definitions (50+ entries)
    // -----------------------------------------------------------------------

    fn register_builtin_schemas(&mut self) {
        // ── View lifecycle ──────────────────────────────────────────────────
        self.register(EventSchema::new(
            "ViewOpened",
            "A new binary view was opened.",
            vec![
                EventField::required("view_id", FieldType::U64, "Unique view identifier"),
                EventField::required("uri", FieldType::String, "URI of the opened file"),
                EventField::required("arch", FieldType::String, "Target CPU architecture"),
            ],
        ));
        self.register(EventSchema::new(
            "ViewClosed",
            "A binary view was closed.",
            vec![EventField::required(
                "view_id",
                FieldType::U64,
                "View identifier",
            )],
        ));
        self.register(EventSchema::new(
            "ViewSaved",
            "A binary view was saved to disk.",
            vec![
                EventField::required("view_id", FieldType::U64, "View identifier"),
                EventField::required("path", FieldType::String, "Path where the view was saved"),
            ],
        ));

        // ── Analysis ────────────────────────────────────────────────────────
        self.register(EventSchema::new(
            "AnalysisStarted",
            "An analysis pass was started.",
            vec![
                EventField::required("view_id", FieldType::U64, "View identifier"),
                EventField::required("pass", FieldType::String, "Name of the analysis pass"),
            ],
        ));
        self.register(EventSchema::new(
            "AnalysisProgress",
            "Progress update from a running analysis pass.",
            vec![
                EventField::required("view_id", FieldType::U64, "View identifier"),
                EventField::required("pass", FieldType::String, "Name of the analysis pass"),
                EventField::required("percent", FieldType::U8, "Completion percentage (0–100)"),
            ],
        ));
        self.register(EventSchema::new(
            "AnalysisCompleted",
            "An analysis pass completed successfully.",
            vec![
                EventField::required("view_id", FieldType::U64, "View identifier"),
                EventField::required("pass", FieldType::String, "Name of the analysis pass"),
            ],
        ));
        self.register(EventSchema::new(
            "AnalysisFailed",
            "An analysis pass failed.",
            vec![
                EventField::required("view_id", FieldType::U64, "View identifier"),
                EventField::required("pass", FieldType::String, "Name of the analysis pass"),
                EventField::required(
                    "error",
                    FieldType::String,
                    "Human-readable error description",
                ),
            ],
        ));

        // ── Functions ───────────────────────────────────────────────────────
        self.register(EventSchema::new(
            "FunctionDefined",
            "A new function was defined or discovered.",
            vec![
                EventField::required("view_id", FieldType::U64, "View identifier"),
                EventField::required("address", FieldType::U64, "Entry-point address"),
                EventField::required("name", FieldType::String, "Function name"),
            ],
        ));
        self.register(EventSchema::new(
            "FunctionRenamed",
            "A function was renamed.",
            vec![
                EventField::required("view_id", FieldType::U64, "View identifier"),
                EventField::required("address", FieldType::U64, "Entry-point address"),
                EventField::required("old_name", FieldType::String, "Previous name"),
                EventField::required("new_name", FieldType::String, "New name"),
            ],
        ));
        self.register(EventSchema::new(
            "FunctionDeleted",
            "A function definition was removed.",
            vec![
                EventField::required("view_id", FieldType::U64, "View identifier"),
                EventField::required("address", FieldType::U64, "Entry-point address"),
            ],
        ));
        self.register(EventSchema::new(
            "FunctionCommented",
            "A function-level comment was added or changed.",
            vec![
                EventField::required("view_id", FieldType::U64, "View identifier"),
                EventField::required("address", FieldType::U64, "Entry-point address"),
                EventField::required("comment", FieldType::String, "Comment text"),
            ],
        ));
        self.register(EventSchema::new(
            "FunctionTagged",
            "A tag was applied to a function.",
            vec![
                EventField::required("view_id", FieldType::U64, "View identifier"),
                EventField::required("address", FieldType::U64, "Entry-point address"),
                EventField::required("tag", FieldType::String, "Tag name"),
            ],
        ));

        // ── Symbols ─────────────────────────────────────────────────────────
        self.register(EventSchema::new(
            "SymbolDefined",
            "A new symbol was defined.",
            vec![
                EventField::required("view_id", FieldType::U64, "View identifier"),
                EventField::required("address", FieldType::U64, "Symbol address"),
                EventField::required("name", FieldType::String, "Symbol name"),
                EventField::required(
                    "kind",
                    FieldType::String,
                    "Symbol kind (function/data/import)",
                ),
                EventField::required("source", FieldType::String, "Source of the symbol"),
            ],
        ));
        self.register(EventSchema::new(
            "SymbolDeleted",
            "A symbol was removed.",
            vec![
                EventField::required("view_id", FieldType::U64, "View identifier"),
                EventField::required("address", FieldType::U64, "Symbol address"),
            ],
        ));
        self.register(EventSchema::new(
            "SymbolImported",
            "Symbols were imported in bulk.",
            vec![
                EventField::required("view_id", FieldType::U64, "View identifier"),
                EventField::required("count", FieldType::U64, "Number of symbols imported"),
                EventField::required(
                    "source",
                    FieldType::String,
                    "Import source (PDB, ELF, etc.)",
                ),
            ],
        ));

        // ── Debugger ────────────────────────────────────────────────────────
        self.register(EventSchema::new(
            "DebuggerAttached",
            "A debugger was attached to a process.",
            vec![
                EventField::required("view_id", FieldType::U64, "View identifier"),
                EventField::required("pid", FieldType::U32, "Target process ID"),
            ],
        ));
        self.register(EventSchema::new(
            "DebuggerDetached",
            "The debugger was detached.",
            vec![EventField::required(
                "view_id",
                FieldType::U64,
                "View identifier",
            )],
        ));
        self.register(EventSchema::new(
            "BreakpointHit",
            "A breakpoint was hit.",
            vec![
                EventField::required("view_id", FieldType::U64, "View identifier"),
                EventField::required("address", FieldType::U64, "Address of the breakpoint"),
                EventField::required(
                    "thread_id",
                    FieldType::U32,
                    "Thread that hit the breakpoint",
                ),
            ],
        ));
        self.register(EventSchema::new(
            "BreakpointSet",
            "A breakpoint was set.",
            vec![
                EventField::required("view_id", FieldType::U64, "View identifier"),
                EventField::required("address", FieldType::U64, "Address of the breakpoint"),
                EventField::required(
                    "breakpoint_id",
                    FieldType::U32,
                    "Unique breakpoint identifier",
                ),
            ],
        ));
        self.register(EventSchema::new(
            "BreakpointCleared",
            "A breakpoint was cleared.",
            vec![
                EventField::required("view_id", FieldType::U64, "View identifier"),
                EventField::required("breakpoint_id", FieldType::U32, "Breakpoint identifier"),
            ],
        ));
        self.register(EventSchema::new(
            "ProcessExited",
            "The debuggee process exited.",
            vec![
                EventField::required("view_id", FieldType::U64, "View identifier"),
                EventField::required("exit_code", FieldType::I32, "Process exit code"),
            ],
        ));
        self.register(EventSchema::new(
            "ThreadCreated",
            "A new thread was created in the debuggee.",
            vec![
                EventField::required("view_id", FieldType::U64, "View identifier"),
                EventField::required("thread_id", FieldType::U32, "New thread ID"),
            ],
        ));
        self.register(EventSchema::new(
            "ThreadExited",
            "A thread exited in the debuggee.",
            vec![
                EventField::required("view_id", FieldType::U64, "View identifier"),
                EventField::required("thread_id", FieldType::U32, "Thread ID"),
            ],
        ));
        self.register(EventSchema::new(
            "StepComplete",
            "A single-step instruction completed.",
            vec![
                EventField::required("view_id", FieldType::U64, "View identifier"),
                EventField::required("address", FieldType::U64, "New instruction pointer"),
                EventField::required("thread_id", FieldType::U32, "Thread that stepped"),
            ],
        ));
        self.register(EventSchema::new(
            "RegisterChanged",
            "A CPU register was changed.",
            vec![
                EventField::required("view_id", FieldType::U64, "View identifier"),
                EventField::required("thread_id", FieldType::U32, "Thread identifier"),
                EventField::required("register", FieldType::String, "Register name"),
                EventField::required("value", FieldType::U64, "New register value"),
            ],
        ));

        // ── Memory ──────────────────────────────────────────────────────────
        self.register(EventSchema::new(
            "MemoryRead",
            "A memory region was read.",
            vec![
                EventField::required("view_id", FieldType::U64, "View identifier"),
                EventField::required("address", FieldType::U64, "Start address"),
                EventField::required("length", FieldType::U64, "Number of bytes read"),
            ],
        ));
        self.register(EventSchema::new(
            "MemoryWritten",
            "A memory region was written.",
            vec![
                EventField::required("view_id", FieldType::U64, "View identifier"),
                EventField::required("address", FieldType::U64, "Start address"),
                EventField::required("length", FieldType::U64, "Number of bytes written"),
            ],
        ));
        self.register(EventSchema::new(
            "MemoryPatched",
            "A memory region was patched.",
            vec![
                EventField::required("view_id", FieldType::U64, "View identifier"),
                EventField::required("address", FieldType::U64, "Start address"),
                EventField::required("length", FieldType::U64, "Number of bytes patched"),
            ],
        ));
        self.register(EventSchema::new(
            "MemoryMapped",
            "A new memory region was mapped.",
            vec![
                EventField::required("view_id", FieldType::U64, "View identifier"),
                EventField::required("address", FieldType::U64, "Start address"),
                EventField::required("length", FieldType::U64, "Region length in bytes"),
                EventField::required("name", FieldType::String, "Region name or description"),
            ],
        ));

        // ── Types ───────────────────────────────────────────────────────────
        self.register(EventSchema::new(
            "TypeDefined",
            "A new type was defined.",
            vec![
                EventField::required("view_id", FieldType::U64, "View identifier"),
                EventField::required("name", FieldType::String, "Type name"),
            ],
        ));
        self.register(EventSchema::new(
            "TypeUpdated",
            "A type definition was updated.",
            vec![
                EventField::required("view_id", FieldType::U64, "View identifier"),
                EventField::required("name", FieldType::String, "Type name"),
            ],
        ));
        self.register(EventSchema::new(
            "TypeDeleted",
            "A type was deleted.",
            vec![
                EventField::required("view_id", FieldType::U64, "View identifier"),
                EventField::required("name", FieldType::String, "Type name"),
            ],
        ));
        self.register(EventSchema::new(
            "TypeImported",
            "Types were imported in bulk.",
            vec![
                EventField::required("view_id", FieldType::U64, "View identifier"),
                EventField::required("count", FieldType::U64, "Number of types imported"),
                EventField::required("source", FieldType::String, "Import source"),
            ],
        ));

        // ── Patches ─────────────────────────────────────────────────────────
        self.register(EventSchema::new(
            "PatchApplied",
            "A binary patch was applied.",
            vec![
                EventField::required("view_id", FieldType::U64, "View identifier"),
                EventField::required("address", FieldType::U64, "Patch start address"),
                EventField::required("length", FieldType::U64, "Patch length in bytes"),
            ],
        ));
        self.register(EventSchema::new(
            "PatchReverted",
            "A binary patch was reverted.",
            vec![
                EventField::required("view_id", FieldType::U64, "View identifier"),
                EventField::required("address", FieldType::U64, "Patch start address"),
            ],
        ));

        // ── Annotations ─────────────────────────────────────────────────────
        self.register(EventSchema::new(
            "CommentAdded",
            "A comment was added at an address.",
            vec![
                EventField::required("view_id", FieldType::U64, "View identifier"),
                EventField::required("address", FieldType::U64, "Address of the comment"),
                EventField::required("text", FieldType::String, "Comment text"),
            ],
        ));
        self.register(EventSchema::new(
            "CommentRemoved",
            "A comment was removed.",
            vec![
                EventField::required("view_id", FieldType::U64, "View identifier"),
                EventField::required("address", FieldType::U64, "Address of the removed comment"),
            ],
        ));
        self.register(EventSchema::new(
            "BookmarkAdded",
            "A bookmark was added.",
            vec![
                EventField::required("view_id", FieldType::U64, "View identifier"),
                EventField::required("address", FieldType::U64, "Bookmarked address"),
                EventField::optional("label", FieldType::String, "Optional bookmark label"),
            ],
        ));
        self.register(EventSchema::new(
            "BookmarkRemoved",
            "A bookmark was removed.",
            vec![
                EventField::required("view_id", FieldType::U64, "View identifier"),
                EventField::required("address", FieldType::U64, "Address"),
            ],
        ));

        // ── Agent / AI ──────────────────────────────────────────────────────
        self.register(EventSchema::new(
            "AgentAction",
            "The AI agent performed an action.",
            vec![
                EventField::required("view_id", FieldType::U64, "View identifier"),
                EventField::required("action", FieldType::String, "Action description"),
                EventField::required("result", FieldType::String, "Action result"),
            ],
        ));
        self.register(EventSchema::new(
            "AgentError",
            "The AI agent encountered an error.",
            vec![
                EventField::required("view_id", FieldType::U64, "View identifier"),
                EventField::required("action", FieldType::String, "Action that failed"),
                EventField::required("error", FieldType::String, "Error description"),
            ],
        ));
        self.register(EventSchema::new(
            "AgentStarted",
            "An AI agent was started.",
            vec![
                EventField::required("view_id", FieldType::U64, "View identifier"),
                EventField::required("agent_name", FieldType::String, "Agent name"),
            ],
        ));
        self.register(EventSchema::new(
            "AgentStopped",
            "An AI agent was stopped.",
            vec![
                EventField::required("view_id", FieldType::U64, "View identifier"),
                EventField::required("agent_name", FieldType::String, "Agent name"),
            ],
        ));

        // ── Cross-references ────────────────────────────────────────────────
        self.register(EventSchema::new(
            "XrefAdded",
            "A cross-reference was added.",
            vec![
                EventField::required("view_id", FieldType::U64, "View identifier"),
                EventField::required("from_addr", FieldType::U64, "Source address"),
                EventField::required("to_addr", FieldType::U64, "Target address"),
                EventField::required("kind", FieldType::String, "Reference kind (call/jump/data)"),
            ],
        ));
        self.register(EventSchema::new(
            "XrefRemoved",
            "A cross-reference was removed.",
            vec![
                EventField::required("view_id", FieldType::U64, "View identifier"),
                EventField::required("from_addr", FieldType::U64, "Source address"),
                EventField::required("to_addr", FieldType::U64, "Target address"),
            ],
        ));

        // ── Script / Plugin ─────────────────────────────────────────────────
        self.register(EventSchema::new(
            "ScriptExecuted",
            "A script was executed.",
            vec![
                EventField::required("view_id", FieldType::U64, "View identifier"),
                EventField::required("engine", FieldType::String, "Script engine name"),
                EventField::required("success", FieldType::Bool, "Whether execution succeeded"),
            ],
        ));
        self.register(EventSchema::new(
            "PluginLoaded",
            "A plugin was loaded.",
            vec![EventField::required(
                "plugin_id",
                FieldType::String,
                "Plugin identifier",
            )],
        ));
        self.register(EventSchema::new(
            "PluginUnloaded",
            "A plugin was unloaded.",
            vec![EventField::required(
                "plugin_id",
                FieldType::String,
                "Plugin identifier",
            )],
        ));
        self.register(EventSchema::new(
            "PluginError",
            "A plugin encountered an error.",
            vec![
                EventField::required("plugin_id", FieldType::String, "Plugin identifier"),
                EventField::required("error", FieldType::String, "Error description"),
            ],
        ));
        self.register(EventSchema::new(
            "TriageCompleted",
            "Automated triage of a binary completed.",
            vec![
                EventField::required("view_id", FieldType::U64, "View identifier"),
                EventField::required("verdict", FieldType::String, "Triage verdict"),
            ],
        ));
        self.register(EventSchema::new(
            "Custom",
            "A custom plugin-defined event.",
            vec![
                EventField::required("event_type", FieldType::String, "Custom event type name"),
                EventField::required("payload", FieldType::Json, "Custom event payload"),
            ],
        ));

        // ── SpecCoreEvent extras ────────────────────────────────────────────
        self.register(EventSchema::new(
            "SymbolAdded",
            "A symbol was added (spec §2.10).",
            vec![
                EventField::required("view_id", FieldType::U64, "View identifier"),
                EventField::required("addr", FieldType::U64, "Symbol address"),
                EventField::required("name", FieldType::String, "Symbol name"),
                EventField::required("kind", FieldType::String, "Symbol kind"),
            ],
        ));
        self.register(EventSchema::new(
            "CommentChanged",
            "A comment was changed (spec §2.10).",
            vec![
                EventField::required("view_id", FieldType::U64, "View identifier"),
                EventField::required("addr", FieldType::U64, "Address"),
                EventField::required("text", FieldType::String, "New comment text"),
            ],
        ));
        self.register(EventSchema::new(
            "BreakpointRemoved",
            "A breakpoint was removed (spec §2.10).",
            vec![
                EventField::required("view_id", FieldType::U64, "View identifier"),
                EventField::required("addr", FieldType::U64, "Breakpoint address"),
            ],
        ));
        self.register(EventSchema::new(
            "ProcessStepped",
            "A step was completed (spec §2.10).",
            vec![
                EventField::required("thread_id", FieldType::U32, "Thread identifier"),
                EventField::required("new_ip", FieldType::U64, "New instruction pointer"),
            ],
        ));
        self.register(EventSchema::new(
            "SandboxCompleted",
            "Sandboxed execution completed.",
            vec![
                EventField::required("job_id", FieldType::String, "Sandbox job identifier"),
                EventField::required(
                    "report_path",
                    FieldType::String,
                    "Path to the sandbox report",
                ),
            ],
        ));
        self.register(EventSchema::new(
            "ScriptOutput",
            "A script produced output.",
            vec![
                EventField::required("source", FieldType::String, "Script source name"),
                EventField::required("message", FieldType::String, "Output message"),
            ],
        ));
    }
}

impl Default for SchemaRegistry {
    fn default() -> Self {
        Self::with_builtin()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_registry() -> SchemaRegistry {
        SchemaRegistry::default()
    }

    // ── SchemaRegistry ───────────────────────────────────────────────────────

    #[test]
    fn registry_has_builtin_schemas() {
        let reg = make_registry();
        assert!(reg.len() >= 50);
    }

    #[test]
    fn registry_contains_function_defined() {
        let reg = make_registry();
        assert!(reg.contains("FunctionDefined"));
    }

    #[test]
    fn registry_contains_all_core_variants() {
        let reg = make_registry();
        let expected = [
            "ViewOpened",
            "ViewClosed",
            "AnalysisStarted",
            "FunctionDefined",
            "BreakpointHit",
            "MemoryRead",
            "TypeDefined",
            "PatchApplied",
            "PluginLoaded",
            "Custom",
        ];
        for et in expected {
            assert!(reg.contains(et), "missing {et}");
        }
    }

    #[test]
    fn registry_get_returns_schema() {
        let reg = make_registry();
        let schema = reg.get("ViewOpened").unwrap();
        assert_eq!(schema.event_type, "ViewOpened");
    }

    #[test]
    fn registry_get_unknown_returns_none() {
        let reg = make_registry();
        assert!(reg.get("NonExistentEvent").is_none());
    }

    #[test]
    fn registry_custom_schema_registration() {
        let mut reg = make_registry();
        let schema = EventSchema::new(
            "MyCustomEvent",
            "Test event",
            vec![EventField::required("id", FieldType::U64, "Identifier")],
        );
        reg.register(schema);
        assert!(reg.contains("MyCustomEvent"));
    }

    #[test]
    fn registry_unregister() {
        let mut reg = make_registry();
        reg.unregister("Custom");
        assert!(!reg.contains("Custom"));
    }

    #[test]
    fn registry_all_schemas_sorted() {
        let reg = make_registry();
        let schemas = reg.all_schemas();
        let names: Vec<&str> = schemas.iter().map(|s| s.event_type.as_str()).collect();
        let mut sorted = names.clone();
        sorted.sort_unstable();
        assert_eq!(names, sorted);
    }

    #[test]
    fn registry_event_types_sorted() {
        let reg = make_registry();
        let types = reg.event_types();
        let mut sorted = types.clone();
        sorted.sort_unstable();
        assert_eq!(types, sorted);
    }

    // ── EventSchema ─────────────────────────────────────────────────────────

    #[test]
    fn schema_required_fields() {
        let reg = make_registry();
        let schema = reg.get("FunctionDefined").unwrap();
        let req: Vec<&str> = schema
            .required_fields()
            .iter()
            .map(|f| f.name.as_str())
            .collect();
        assert!(req.contains(&"view_id"));
        assert!(req.contains(&"address"));
        assert!(req.contains(&"name"));
    }

    #[test]
    fn schema_optional_fields_for_bookmark() {
        let reg = make_registry();
        let schema = reg.get("BookmarkAdded").unwrap();
        let opt: Vec<&str> = schema
            .optional_fields()
            .iter()
            .map(|f| f.name.as_str())
            .collect();
        assert!(opt.contains(&"label"));
    }

    #[test]
    fn schema_field_lookup() {
        let reg = make_registry();
        let schema = reg.get("BreakpointHit").unwrap();
        let f = schema.field("address").unwrap();
        assert_eq!(f.field_type, FieldType::U64);
    }

    #[test]
    fn schema_display() {
        let reg = make_registry();
        let schema = reg.get("ViewOpened").unwrap();
        let s = schema.to_string();
        assert!(s.contains("ViewOpened"));
    }

    #[test]
    fn schema_to_json_schema() {
        let reg = make_registry();
        let schema = reg.get("FunctionDefined").unwrap();
        let js = schema.to_json_schema();
        assert_eq!(js["title"], "FunctionDefined");
        assert!(js["properties"]["view_id"].is_object());
    }

    #[test]
    fn schema_deprecated_by() {
        let schema = EventSchema::new("OldEvent", "Old", vec![]).deprecated_by("NewEvent");
        assert!(schema.deprecated);
        assert_eq!(schema.replaced_by.as_deref(), Some("NewEvent"));
    }

    // ── EventField ──────────────────────────────────────────────────────────

    #[test]
    fn event_field_required() {
        let f = EventField::required("name", FieldType::String, "A name");
        assert!(f.required);
        assert_eq!(f.field_type, FieldType::String);
    }

    #[test]
    fn event_field_optional() {
        let f = EventField::optional("label", FieldType::String, "Optional label");
        assert!(!f.required);
        assert!(matches!(f.field_type, FieldType::Optional(_)));
    }

    #[test]
    fn event_field_display() {
        let f = EventField::required("address", FieldType::U64, "Address field");
        let s = f.to_string();
        assert!(s.contains("address"));
        assert!(s.contains("u64"));
    }

    // ── SchemaValidator ─────────────────────────────────────────────────────

    #[test]
    fn validator_valid_payload() {
        let reg = make_registry();
        let v = SchemaValidator::new(&reg);
        let payload = serde_json::json!({ "view_id": 1u64, "address": 0x1000u64, "name": "main" });
        assert!(v.validate("FunctionDefined", &payload).is_ok());
    }

    #[test]
    fn validator_missing_required_field() {
        let reg = make_registry();
        let v = SchemaValidator::new(&reg);
        let payload = serde_json::json!({ "view_id": 1u64, "address": 0x1000u64 });
        let err = v.validate("FunctionDefined", &payload).unwrap_err();
        assert!(matches!(err, ValidationError::MissingField(f) if f == "name"));
    }

    #[test]
    fn validator_unknown_event_type() {
        let reg = make_registry();
        let v = SchemaValidator::new(&reg);
        let err = v
            .validate("NoSuchEvent", &serde_json::json!({}))
            .unwrap_err();
        assert!(matches!(err, ValidationError::UnknownEventType(_)));
    }

    #[test]
    fn validator_strict_rejects_extra_fields() {
        let reg = make_registry();
        let v = SchemaValidator::new(&reg).strict();
        let payload = serde_json::json!({
            "view_id": 1u64,
            "address": 0x1000u64,
            "name": "foo",
            "extra_field": true,
        });
        let err = v.validate("FunctionDefined", &payload).unwrap_err();
        assert!(matches!(err, ValidationError::UnknownField(_)));
    }

    #[test]
    fn validator_non_strict_allows_extra_fields() {
        let reg = make_registry();
        let v = SchemaValidator::new(&reg);
        let payload = serde_json::json!({
            "view_id": 1u64,
            "address": 0x1000u64,
            "name": "foo",
            "extra": "ok",
        });
        assert!(v.validate("FunctionDefined", &payload).is_ok());
    }

    #[test]
    fn validator_wrong_type() {
        let reg = make_registry();
        let v = SchemaValidator::new(&reg);
        // view_id should be a number, not a string
        let payload =
            serde_json::json!({ "view_id": "not-a-number", "address": 0u64, "name": "f" });
        let err = v.validate("FunctionDefined", &payload).unwrap_err();
        assert!(matches!(err, ValidationError::WrongType { .. }));
    }

    #[test]
    fn validator_batch_validation() {
        let reg = make_registry();
        let v = SchemaValidator::new(&reg);
        let items = vec![
            (
                "FunctionDefined".to_string(),
                serde_json::json!({ "view_id": 1u64, "address": 0u64, "name": "f" }),
            ),
            (
                "FunctionDefined".to_string(),
                serde_json::json!({ "view_id": 1u64 }),
            ), // missing fields
        ];
        let errors = v.validate_batch(&items);
        assert_eq!(errors.len(), 1);
    }

    // ── SchemaExporter ──────────────────────────────────────────────────────

    #[test]
    fn exporter_export_all_has_schemas_key() {
        let reg = make_registry();
        let exported = SchemaExporter::export_all(&reg);
        assert!(exported["schemas"].is_object());
    }

    #[test]
    fn exporter_export_one_some() {
        let reg = make_registry();
        let js = SchemaExporter::export_one(&reg, "ViewOpened").unwrap();
        assert_eq!(js["title"], "ViewOpened");
    }

    #[test]
    fn exporter_export_one_none() {
        let reg = make_registry();
        assert!(SchemaExporter::export_one(&reg, "NonExistent").is_none());
    }

    #[test]
    fn exporter_to_json_string() {
        let reg = make_registry();
        let s = SchemaExporter::to_json_string(&reg).unwrap();
        assert!(s.contains("ViewOpened"));
    }

    // ── SchemaVersion ───────────────────────────────────────────────────────

    #[test]
    fn schema_version_display() {
        let v = SchemaVersion::new(2, 3, 1);
        assert_eq!(v.to_string(), "2.3.1");
    }

    #[test]
    fn schema_version_v1() {
        let v = SchemaVersion::v1();
        assert_eq!(v.major, 1);
        assert_eq!(v.minor, 0);
    }

    #[test]
    fn schema_version_compatibility() {
        let v1 = SchemaVersion::new(1, 2, 0);
        let v2 = SchemaVersion::new(1, 1, 0);
        assert!(v1.is_compatible_with(v2));
        assert!(!v2.is_compatible_with(v1));
    }

    // ── MigrationScript ─────────────────────────────────────────────────────

    #[test]
    fn migration_apply_rename() {
        let script = MigrationScript::new(
            "FunctionDefined",
            SchemaVersion::v1(),
            SchemaVersion::new(2, 0, 0),
            "rename addr to address",
        )
        .rename("addr", "address");
        let payload = serde_json::json!({ "view_id": 1u64, "addr": 0x1000u64, "name": "foo" });
        let migrated = script.apply(payload);
        assert!(migrated["address"].is_number());
        assert!(migrated.get("addr").is_none());
    }

    #[test]
    fn migration_apply_add_field() {
        let script = MigrationScript::new(
            "Event",
            SchemaVersion::v1(),
            SchemaVersion::new(2, 0, 0),
            "add arch",
        )
        .add_field("arch", serde_json::json!("unknown"));
        let payload = serde_json::json!({ "view_id": 1u64 });
        let migrated = script.apply(payload);
        assert_eq!(migrated["arch"], "unknown");
    }

    #[test]
    fn migration_apply_remove_field() {
        let script = MigrationScript::new(
            "Event",
            SchemaVersion::v1(),
            SchemaVersion::new(2, 0, 0),
            "remove legacy",
        )
        .remove_field("legacy");
        let payload = serde_json::json!({ "view_id": 1u64, "legacy": true });
        let migrated = script.apply(payload);
        assert!(migrated.get("legacy").is_none());
    }

    #[test]
    fn migration_display() {
        let script = MigrationScript::new(
            "E",
            SchemaVersion::v1(),
            SchemaVersion::new(2, 0, 0),
            "test",
        );
        let s = script.to_string();
        assert!(s.contains('E'));
        assert!(s.contains("1.0.0"));
        assert!(s.contains("2.0.0"));
    }

    // ── Registry migration integration ──────────────────────────────────────

    #[test]
    fn registry_find_migration() {
        let mut reg = make_registry();
        let script = MigrationScript::new(
            "FunctionDefined",
            SchemaVersion::v1(),
            SchemaVersion::new(2, 0, 0),
            "rename",
        );
        reg.add_migration(script);
        let found = reg.find_migration(
            "FunctionDefined",
            SchemaVersion::v1(),
            SchemaVersion::new(2, 0, 0),
        );
        assert!(found.is_some());
    }

    #[test]
    fn registry_migrate_applies_script() {
        let mut reg = make_registry();
        reg.add_migration(
            MigrationScript::new(
                "FunctionDefined",
                SchemaVersion::v1(),
                SchemaVersion::new(2, 0, 0),
                "rename",
            )
            .rename("view_id", "vid"),
        );
        let payload = serde_json::json!({ "view_id": 42u64, "address": 0u64, "name": "f" });
        let migrated = reg.migrate(
            "FunctionDefined",
            SchemaVersion::v1(),
            SchemaVersion::new(2, 0, 0),
            payload,
        );
        assert!(migrated["vid"].is_number());
    }

    #[test]
    fn registry_migrate_noop_when_no_script() {
        let reg = make_registry();
        let payload = serde_json::json!({ "foo": 1 });
        let result = reg.migrate(
            "FunctionDefined",
            SchemaVersion::v1(),
            SchemaVersion::new(99, 0, 0),
            payload.clone(),
        );
        assert_eq!(result, payload);
    }

    // ── FieldType display ───────────────────────────────────────────────────

    #[test]
    fn field_type_display_optional() {
        let ft = FieldType::Optional(Box::new(FieldType::String));
        assert_eq!(ft.to_string(), "?string");
    }

    #[test]
    fn field_type_display_array() {
        let ft = FieldType::Array(Box::new(FieldType::U64));
        assert_eq!(ft.to_string(), "[u64]");
    }

    #[test]
    fn field_type_display_primitives() {
        assert_eq!(FieldType::U64.to_string(), "u64");
        assert_eq!(FieldType::Bool.to_string(), "bool");
        assert_eq!(FieldType::Json.to_string(), "json");
    }
}
