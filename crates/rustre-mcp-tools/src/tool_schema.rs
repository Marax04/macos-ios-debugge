//! MCP tool schema — **primitive layer**.
//!
//! Provides the low-level building blocks used throughout the crate:
//! [`SchemaType`], [`SchemaProperty`], [`ToolParameterSchema`], the fluent
//! [`SchemaBuilder`], validation returning <code>Vec<[SchemaValidationError]></code>,
//! and pre-built schemas for common RE tool parameters.
//!
//! The higher-level manifest / registry layer lives in [`super::tool_schemas`]:
//! it owns [`super::tool_schemas::ToolManifest`], [`super::tool_schemas::ToolSchemas`],
//! [`super::tool_schemas::ResponseSchema`], and [`super::tool_schemas::SchemaValidator`].
//! That layer has its own `SchemaProperty` (with an embedded `name` and `required`
//! flag) suited for declarative manifest construction; it re-exports [`SchemaType`]
//! from this module to avoid duplication.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

// ──────────────────────────────────────────────────────────────────────────────
// JSON Schema primitives
// ──────────────────────────────────────────────────────────────────────────────

/// A JSON Schema type.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SchemaType {
    String,
    Number,
    Integer,
    Boolean,
    Array,
    Object,
    Null,
}

impl SchemaType {
    /// JSON Schema `type` string.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::String => "string",
            Self::Number => "number",
            Self::Integer => "integer",
            Self::Boolean => "boolean",
            Self::Array => "array",
            Self::Object => "object",
            Self::Null => "null",
        }
    }

    /// Returns `true` when `v` is an instance of this JSON Schema type.
    ///
    /// Migrated from the registry layer (`tool_schemas`) to avoid duplicate
    /// `SchemaType` definitions across the two modules.
    #[must_use]
    pub fn matches_value(&self, v: &serde_json::Value) -> bool {
        match self {
            Self::String => v.is_string(),
            Self::Integer => v.is_i64() || v.is_u64(),
            Self::Number => v.is_number(),
            Self::Boolean => v.is_boolean(),
            Self::Array => v.is_array(),
            Self::Object => v.is_object(),
            Self::Null => v.is_null(),
        }
    }
}

impl std::fmt::Display for SchemaType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// SchemaProperty
// ──────────────────────────────────────────────────────────────────────────────

/// A single property in an object schema.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchemaProperty {
    #[serde(rename = "type")]
    pub schema_type: SchemaType,
    pub description: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub minimum: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub maximum: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_length: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_length: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pattern: Option<String>,
    #[serde(rename = "enum", default, skip_serializing_if = "Vec::is_empty")]
    pub enum_values: Vec<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub items: Option<Box<SchemaProperty>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub example: Option<Value>,
}

impl SchemaProperty {
    /// Create a string property.
    #[must_use]
    pub fn string(description: impl Into<String>) -> Self {
        Self {
            schema_type: SchemaType::String,
            description: description.into(),
            default: None,
            minimum: None,
            maximum: None,
            min_length: None,
            max_length: None,
            pattern: None,
            enum_values: Vec::new(),
            items: None,
            format: None,
            example: None,
        }
    }

    /// Create an integer property.
    #[must_use]
    pub fn integer(description: impl Into<String>) -> Self {
        Self { schema_type: SchemaType::Integer, description: description.into(), ..Self::null_stub() }
    }

    /// Create a number property.
    #[must_use]
    pub fn number(description: impl Into<String>) -> Self {
        Self { schema_type: SchemaType::Number, description: description.into(), ..Self::null_stub() }
    }

    /// Create a boolean property.
    #[must_use]
    pub fn boolean(description: impl Into<String>) -> Self {
        Self { schema_type: SchemaType::Boolean, description: description.into(), ..Self::null_stub() }
    }

    /// Create an array property.
    #[must_use]
    pub fn array(description: impl Into<String>, items: SchemaProperty) -> Self {
        Self {
            schema_type: SchemaType::Array,
            description: description.into(),
            items: Some(Box::new(items)),
            ..Self::null_stub()
        }
    }

    /// Create an object property.
    #[must_use]
    pub fn object(description: impl Into<String>) -> Self {
        Self { schema_type: SchemaType::Object, description: description.into(), ..Self::null_stub() }
    }

    fn null_stub() -> Self {
        Self {
            schema_type: SchemaType::Null,
            description: String::new(),
            default: None,
            minimum: None,
            maximum: None,
            min_length: None,
            max_length: None,
            pattern: None,
            enum_values: Vec::new(),
            items: None,
            format: None,
            example: None,
        }
    }

    /// Set a default value.
    #[must_use]
    pub fn with_default(mut self, v: Value) -> Self {
        self.default = Some(v);
        self
    }

    /// Set a minimum value.
    #[must_use]
    pub fn with_minimum(mut self, min: f64) -> Self {
        self.minimum = Some(min);
        self
    }

    /// Set a maximum value.
    #[must_use]
    pub fn with_maximum(mut self, max: f64) -> Self {
        self.maximum = Some(max);
        self
    }

    /// Set a pattern (for strings).
    #[must_use]
    pub fn with_pattern(mut self, p: impl Into<String>) -> Self {
        self.pattern = Some(p.into());
        self
    }

    /// Set an enum.
    #[must_use]
    pub fn with_enum(mut self, values: Vec<Value>) -> Self {
        self.enum_values = values;
        self
    }

    /// Set a format hint.
    #[must_use]
    pub fn with_format(mut self, fmt: impl Into<String>) -> Self {
        self.format = Some(fmt.into());
        self
    }

    /// Set an example.
    #[must_use]
    pub fn with_example(mut self, ex: Value) -> Self {
        self.example = Some(ex);
        self
    }

    /// Convert this property to a `serde_json::Value`.
    #[must_use]
    pub fn to_json(&self) -> Value {
        let mut m = serde_json::Map::new();
        m.insert("type".to_string(), json!(self.schema_type.as_str()));
        if !self.description.is_empty() {
            m.insert("description".to_string(), json!(self.description));
        }
        if let Some(d) = &self.default { m.insert("default".to_string(), d.clone()); }
        if let Some(min) = self.minimum { m.insert("minimum".to_string(), json!(min)); }
        if let Some(max) = self.maximum { m.insert("maximum".to_string(), json!(max)); }
        if let Some(ml) = self.min_length { m.insert("minLength".to_string(), json!(ml)); }
        if let Some(ml) = self.max_length { m.insert("maxLength".to_string(), json!(ml)); }
        if let Some(p) = &self.pattern { m.insert("pattern".to_string(), json!(p)); }
        if !self.enum_values.is_empty() {
            m.insert("enum".to_string(), Value::Array(self.enum_values.clone()));
        }
        if let Some(items) = &self.items {
            m.insert("items".to_string(), items.to_json());
        }
        if let Some(fmt) = &self.format { m.insert("format".to_string(), json!(fmt)); }
        if let Some(ex) = &self.example { m.insert("example".to_string(), ex.clone()); }
        Value::Object(m)
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// ToolParameterSchema
// ──────────────────────────────────────────────────────────────────────────────

/// The complete parameter schema for one MCP tool.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolParameterSchema {
    #[serde(rename = "type")]
    pub schema_type: String,
    pub properties: HashMap<String, SchemaProperty>,
    pub required: Vec<String>,
    #[serde(rename = "additionalProperties")]
    pub additional_properties: bool,
    pub description: Option<String>,
}

impl ToolParameterSchema {
    /// Create an empty schema.
    #[must_use]
    pub fn new() -> Self {
        Self {
            schema_type: "object".to_string(),
            properties: HashMap::new(),
            required: Vec::new(),
            additional_properties: false,
            description: None,
        }
    }

    /// Add a required property.
    #[must_use]
    pub fn with_required(mut self, name: impl Into<String>, prop: SchemaProperty) -> Self {
        let name = name.into();
        self.required.push(name.clone());
        self.properties.insert(name, prop);
        self
    }

    /// Add an optional property.
    #[must_use]
    pub fn with_optional(mut self, name: impl Into<String>, prop: SchemaProperty) -> Self {
        self.properties.insert(name.into(), prop);
        self
    }

    /// Allow additional properties.
    #[must_use]
    pub const fn allow_additional(mut self) -> Self {
        self.additional_properties = true;
        self
    }

    /// Serialize to `serde_json::Value`.
    #[must_use]
    pub fn to_json(&self) -> Value {
        let mut props = serde_json::Map::new();
        for (name, prop) in &self.properties {
            props.insert(name.clone(), prop.to_json());
        }
        let mut m = serde_json::Map::new();
        m.insert("type".to_string(), json!("object"));
        m.insert("properties".to_string(), Value::Object(props));
        if !self.required.is_empty() {
            m.insert("required".to_string(), json!(self.required));
        }
        m.insert("additionalProperties".to_string(), json!(self.additional_properties));
        if let Some(d) = &self.description {
            m.insert("description".to_string(), json!(d));
        }
        Value::Object(m)
    }
}

impl Default for ToolParameterSchema {
    fn default() -> Self {
        Self::new()
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Schema validation
// ──────────────────────────────────────────────────────────────────────────────

/// Validation error from schema checking.
#[derive(Debug, Clone, thiserror::Error)]
pub enum SchemaValidationError {
    #[error("missing required field: {0}")]
    MissingRequired(String),
    #[error("field '{field}' has wrong type: expected {expected}, got {got}")]
    WrongType { field: String, expected: String, got: String },
    #[error("field '{field}' value {value} is below minimum {min}")]
    BelowMinimum { field: String, value: f64, min: f64 },
    #[error("field '{field}' value {value} exceeds maximum {max}")]
    ExceedsMaximum { field: String, value: f64, max: f64 },
    #[error("field '{field}' length {len} is below minLength {min_len}")]
    TooShort { field: String, len: usize, min_len: u64 },
    #[error("field '{field}' length {len} exceeds maxLength {max_len}")]
    TooLong { field: String, len: usize, max_len: u64 },
    #[error("field '{field}' value is not in enum")]
    NotInEnum { field: String },
    #[error("additional property '{0}' not allowed")]
    AdditionalProperty(String),
}

/// Validate a JSON value against a tool parameter schema.
///
/// Returns all validation errors found (not just the first).
#[must_use]
pub fn validate(schema: &ToolParameterSchema, params: &Value) -> Vec<SchemaValidationError> {
    let mut errors = Vec::new();

    let obj = match params.as_object() {
        Some(o) => o,
        None => {
            errors.push(SchemaValidationError::WrongType {
                field: "<root>".to_string(),
                expected: "object".to_string(),
                got: json_type_name(params).to_string(),
            });
            return errors;
        }
    };

    // Check required fields
    for req in &schema.required {
        if !obj.contains_key(req.as_str()) {
            errors.push(SchemaValidationError::MissingRequired(req.clone()));
        }
    }

    // Check property types and constraints
    for (name, value) in obj {
        if let Some(prop) = schema.properties.get(name.as_str()) {
            errors.extend(validate_property(name, value, prop));
        } else if !schema.additional_properties {
            errors.push(SchemaValidationError::AdditionalProperty(name.clone()));
        }
    }

    errors
}

fn validate_property(
    name: &str,
    value: &Value,
    prop: &SchemaProperty,
) -> Vec<SchemaValidationError> {
    let mut errors = Vec::new();

    // Type check
    let actual_type = json_type_name(value);
    let expected_type = prop.schema_type.as_str();
    let type_ok = match &prop.schema_type {
        SchemaType::Integer => value.is_i64() || value.is_u64(),
        SchemaType::Number => value.is_f64() || value.is_i64() || value.is_u64(),
        SchemaType::String => value.is_string(),
        SchemaType::Boolean => value.is_boolean(),
        SchemaType::Array => value.is_array(),
        SchemaType::Object => value.is_object(),
        SchemaType::Null => value.is_null(),
    };

    if !type_ok {
        errors.push(SchemaValidationError::WrongType {
            field: name.to_string(),
            expected: expected_type.to_string(),
            got: actual_type.to_string(),
        });
        return errors; // further checks are type-dependent
    }

    // Numeric bounds
    if let Some(n) = value.as_f64() {
        if let Some(min) = prop.minimum {
            if n < min {
                errors.push(SchemaValidationError::BelowMinimum {
                    field: name.to_string(),
                    value: n,
                    min,
                });
            }
        }
        if let Some(max) = prop.maximum {
            if n > max {
                errors.push(SchemaValidationError::ExceedsMaximum {
                    field: name.to_string(),
                    value: n,
                    max,
                });
            }
        }
    }

    // String length
    if let Some(s) = value.as_str() {
        let len = s.len();
        if let Some(min_len) = prop.min_length {
            if (len as u64) < min_len {
                errors.push(SchemaValidationError::TooShort {
                    field: name.to_string(),
                    len,
                    min_len,
                });
            }
        }
        if let Some(max_len) = prop.max_length {
            if (len as u64) > max_len {
                errors.push(SchemaValidationError::TooLong {
                    field: name.to_string(),
                    len,
                    max_len,
                });
            }
        }
    }

    // Enum check
    if !prop.enum_values.is_empty() && !prop.enum_values.contains(value) {
        errors.push(SchemaValidationError::NotInEnum { field: name.to_string() });
    }

    errors
}

pub(crate) fn json_type_name(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(n) if n.is_i64() || n.is_u64() => "integer",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Type mapping (Rust → JSON Schema)
// ──────────────────────────────────────────────────────────────────────────────

/// Rust primitive type → JSON Schema type string.
#[must_use]
pub fn rust_type_to_schema_type(rust_type: &str) -> SchemaType {
    match rust_type.trim() {
        "u8" | "u16" | "u32" | "u64" | "u128" | "usize"
        | "i8" | "i16" | "i32" | "i64" | "i128" | "isize" => SchemaType::Integer,
        "f32" | "f64" => SchemaType::Number,
        "bool" => SchemaType::Boolean,
        "String" | "&str" | "&'static str" => SchemaType::String,
        t if t.starts_with("Vec<") || t.ends_with(']') => SchemaType::Array,
        t if t.starts_with("HashMap") || t.starts_with("BTreeMap") => SchemaType::Object,
        _ => SchemaType::Object,
    }
}

/// A descriptor for one Rust field, used for automatic schema generation.
#[derive(Debug, Clone)]
pub struct FieldDescriptor {
    pub name: String,
    pub rust_type: String,
    pub description: String,
    pub required: bool,
    pub default: Option<Value>,
    pub minimum: Option<f64>,
    pub maximum: Option<f64>,
    pub enum_values: Vec<Value>,
}

impl FieldDescriptor {
    /// Create a required field.
    #[must_use]
    pub fn required(name: &str, rust_type: &str, description: &str) -> Self {
        Self {
            name: name.to_string(),
            rust_type: rust_type.to_string(),
            description: description.to_string(),
            required: true,
            default: None,
            minimum: None,
            maximum: None,
            enum_values: Vec::new(),
        }
    }

    /// Create an optional field.
    #[must_use]
    pub fn optional(name: &str, rust_type: &str, description: &str) -> Self {
        Self { required: false, ..Self::required(name, rust_type, description) }
    }

    /// Convert to a `SchemaProperty`.
    #[must_use]
    pub fn to_property(&self) -> SchemaProperty {
        let schema_type = rust_type_to_schema_type(&self.rust_type);
        let mut prop = SchemaProperty {
            schema_type,
            description: self.description.clone(),
            default: self.default.clone(),
            minimum: self.minimum,
            maximum: self.maximum,
            min_length: None,
            max_length: None,
            pattern: None,
            enum_values: self.enum_values.clone(),
            items: None,
            format: None,
            example: None,
        };

        // Infer items for Vec types
        if self.rust_type.starts_with("Vec<") {
            let inner = &self.rust_type[4..self.rust_type.len() - 1];
            let inner_type = rust_type_to_schema_type(inner);
            prop.items = Some(Box::new(SchemaProperty {
                schema_type: inner_type,
                description: format!("element of {}", self.rust_type),
                ..SchemaProperty::null_stub()
            }));
        }

        prop
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// SchemaBuilder — fluent API for constructing tool schemas
// ──────────────────────────────────────────────────────────────────────────────

/// Builder for `ToolParameterSchema`.
#[derive(Debug, Default)]
pub struct SchemaBuilder {
    schema: ToolParameterSchema,
}

impl SchemaBuilder {
    /// Create a new builder.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a required string field.
    #[must_use]
    pub fn req_string(mut self, name: &str, desc: &str) -> Self {
        let prop = SchemaProperty::string(desc);
        self.schema.required.push(name.to_string());
        self.schema.properties.insert(name.to_string(), prop);
        self
    }

    /// Add a required integer field.
    #[must_use]
    pub fn req_integer(mut self, name: &str, desc: &str) -> Self {
        let prop = SchemaProperty::integer(desc);
        self.schema.required.push(name.to_string());
        self.schema.properties.insert(name.to_string(), prop);
        self
    }

    /// Add an optional string field with default.
    #[must_use]
    pub fn opt_string(mut self, name: &str, desc: &str, default: &str) -> Self {
        let prop = SchemaProperty::string(desc).with_default(json!(default));
        self.schema.properties.insert(name.to_string(), prop);
        self
    }

    /// Add an optional boolean field.
    #[must_use]
    pub fn opt_bool(mut self, name: &str, desc: &str, default: bool) -> Self {
        let prop = SchemaProperty::boolean(desc).with_default(json!(default));
        self.schema.properties.insert(name.to_string(), prop);
        self
    }

    /// Add an optional integer field.
    #[must_use]
    pub fn opt_integer(mut self, name: &str, desc: &str, default: i64) -> Self {
        let prop = SchemaProperty::integer(desc).with_default(json!(default));
        self.schema.properties.insert(name.to_string(), prop);
        self
    }

    /// Add a field with min/max bounds.
    #[must_use]
    pub fn bounded_integer(mut self, name: &str, desc: &str, min: f64, max: f64, required: bool) -> Self {
        let prop = SchemaProperty::integer(desc)
            .with_minimum(min)
            .with_maximum(max);
        if required {
            self.schema.required.push(name.to_string());
        }
        self.schema.properties.insert(name.to_string(), prop);
        self
    }

    /// Add an enum field.
    #[must_use]
    pub fn enum_field(mut self, name: &str, desc: &str, values: Vec<&str>, required: bool) -> Self {
        let enum_vals: Vec<Value> = values.iter().map(|s| json!(s)).collect();
        let prop = SchemaProperty::string(desc).with_enum(enum_vals);
        if required {
            self.schema.required.push(name.to_string());
        }
        self.schema.properties.insert(name.to_string(), prop);
        self
    }

    /// Generate schema from field descriptors.
    #[must_use]
    pub fn from_fields(fields: Vec<FieldDescriptor>) -> ToolParameterSchema {
        let mut schema = ToolParameterSchema::new();
        for field in fields {
            let prop = field.to_property();
            if field.required {
                schema.required.push(field.name.clone());
            }
            schema.properties.insert(field.name, prop);
        }
        schema
    }

    /// Build the schema.
    #[must_use]
    pub fn build(self) -> ToolParameterSchema {
        self.schema
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Common schemas for RE tools
// ──────────────────────────────────────────────────────────────────────────────

/// Build the schema for `disassemble_at`.
#[must_use]
pub fn disassemble_at_schema() -> ToolParameterSchema {
    SchemaBuilder::new()
        .req_integer("address", "Virtual address to disassemble at (hex or decimal)")
        .bounded_integer("count", "Number of instructions to disassemble", 1.0, 1000.0, false)
        .opt_string("arch", "Architecture (x86, x86_64, arm, arm64)", "x86_64")
        .build()
}

/// Build the schema for `get_function`.
#[must_use]
pub fn get_function_schema() -> ToolParameterSchema {
    SchemaBuilder::new()
        .req_string("name", "Function name or address (hex)")
        .opt_bool("decompile", "Include decompiled pseudocode", false)
        .opt_bool("disassemble", "Include disassembly", true)
        .build()
}

/// Build the schema for `list_functions`.
#[must_use]
pub fn list_functions_schema() -> ToolParameterSchema {
    SchemaBuilder::new()
        .opt_string("filter", "Filter by name prefix or regex", "")
        .bounded_integer("limit", "Maximum number of results", 1.0, 10000.0, false)
        .bounded_integer("offset", "Pagination offset", 0.0, 1_000_000.0, false)
        .build()
}

/// Build the schema for `search_string`.
#[must_use]
pub fn search_string_schema() -> ToolParameterSchema {
    SchemaBuilder::new()
        .req_string("pattern", "String or regex to search for")
        .opt_bool("case_sensitive", "Case-sensitive search", false)
        .opt_bool("regex", "Treat pattern as a regular expression", false)
        .bounded_integer("min_length", "Minimum string length", 1.0, 10000.0, false)
        .bounded_integer("limit", "Maximum results", 1.0, 10000.0, false)
        .build()
}

/// Build the schema for `compute_hash`.
#[must_use]
pub fn compute_hash_schema() -> ToolParameterSchema {
    SchemaBuilder::new()
        .req_string("data", "Hex-encoded bytes or base64-encoded data")
        .enum_field(
            "algorithm",
            "Hash algorithm",
            vec!["md5", "sha1", "sha256", "sha512", "crc32"],
            false,
        )
        .build()
}

/// Build the schema for `get_section`.
#[must_use]
pub fn get_section_schema() -> ToolParameterSchema {
    SchemaBuilder::new()
        .req_string("name", "Section name (e.g. '.text', '.data')")
        .opt_bool("include_data", "Include section raw bytes (hex)", false)
        .build()
}

// ──────────────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_schema_type_as_str() {
        assert_eq!(SchemaType::String.as_str(), "string");
        assert_eq!(SchemaType::Integer.as_str(), "integer");
        assert_eq!(SchemaType::Boolean.as_str(), "boolean");
        assert_eq!(SchemaType::Array.as_str(), "array");
    }

    #[test]
    fn test_property_to_json_string() {
        let p = SchemaProperty::string("A test field");
        let j = p.to_json();
        assert_eq!(j["type"], "string");
        assert_eq!(j["description"], "A test field");
    }

    #[test]
    fn test_property_with_default() {
        let p = SchemaProperty::integer("Count").with_default(json!(10));
        let j = p.to_json();
        assert_eq!(j["default"], 10);
    }

    #[test]
    fn test_property_with_bounds() {
        let p = SchemaProperty::integer("Port")
            .with_minimum(1.0)
            .with_maximum(65535.0);
        let j = p.to_json();
        assert_eq!(j["minimum"], 1.0);
        assert_eq!(j["maximum"], 65535.0);
    }

    #[test]
    fn test_property_with_enum() {
        let p = SchemaProperty::string("Mode")
            .with_enum(vec![json!("read"), json!("write")]);
        let j = p.to_json();
        assert!(j["enum"].is_array());
    }

    #[test]
    fn test_schema_to_json() {
        let schema = SchemaBuilder::new()
            .req_string("name", "A name")
            .opt_integer("count", "A count", 10)
            .build();
        let j = schema.to_json();
        assert_eq!(j["type"], "object");
        assert!(j["properties"]["name"].is_object());
        assert!(j["required"].as_array().unwrap().contains(&json!("name")));
    }

    #[test]
    fn test_validate_missing_required() {
        let schema = SchemaBuilder::new()
            .req_string("address", "address")
            .build();
        let params = json!({});
        let errors = validate(&schema, &params);
        assert!(!errors.is_empty());
        assert!(matches!(errors[0], SchemaValidationError::MissingRequired(_)));
    }

    #[test]
    fn test_validate_wrong_type() {
        let schema = SchemaBuilder::new()
            .req_integer("count", "count")
            .build();
        let params = json!({"count": "not a number"});
        let errors = validate(&schema, &params);
        assert!(!errors.is_empty());
        assert!(matches!(errors[0], SchemaValidationError::WrongType { .. }));
    }

    #[test]
    fn test_validate_below_minimum() {
        let schema = SchemaBuilder::new()
            .bounded_integer("port", "port", 1.0, 65535.0, true)
            .build();
        let params = json!({"port": 0});
        let errors = validate(&schema, &params);
        assert!(!errors.is_empty());
        assert!(matches!(errors[0], SchemaValidationError::BelowMinimum { .. }));
    }

    #[test]
    fn test_validate_exceeds_maximum() {
        let schema = SchemaBuilder::new()
            .bounded_integer("port", "port", 1.0, 65535.0, true)
            .build();
        let params = json!({"port": 99999});
        let errors = validate(&schema, &params);
        assert!(!errors.is_empty());
        assert!(matches!(errors[0], SchemaValidationError::ExceedsMaximum { .. }));
    }

    #[test]
    fn test_validate_valid_params() {
        let schema = disassemble_at_schema();
        let params = json!({"address": 0x1000});
        let errors = validate(&schema, &params);
        assert!(errors.is_empty(), "{errors:?}");
    }

    #[test]
    fn test_validate_additional_property() {
        let schema = ToolParameterSchema::new()
            .with_required("x", SchemaProperty::integer("x"));
        let params = json!({"x": 1, "unexpected": true});
        let errors = validate(&schema, &params);
        assert!(errors.iter().any(|e| matches!(e, SchemaValidationError::AdditionalProperty(_))));
    }

    #[test]
    fn test_rust_type_to_schema_type() {
        assert_eq!(rust_type_to_schema_type("u64"), SchemaType::Integer);
        assert_eq!(rust_type_to_schema_type("f64"), SchemaType::Number);
        assert_eq!(rust_type_to_schema_type("bool"), SchemaType::Boolean);
        assert_eq!(rust_type_to_schema_type("String"), SchemaType::String);
        assert_eq!(rust_type_to_schema_type("Vec<u8>"), SchemaType::Array);
    }

    #[test]
    fn test_field_descriptor_to_property() {
        let f = FieldDescriptor::required("addr", "u64", "address");
        let p = f.to_property();
        assert_eq!(p.schema_type, SchemaType::Integer);
    }

    #[test]
    fn test_schema_builder_from_fields() {
        let fields = vec![
            FieldDescriptor::required("name", "String", "function name"),
            FieldDescriptor::optional("count", "u32", "limit"),
        ];
        let schema = SchemaBuilder::from_fields(fields);
        assert!(schema.required.contains(&"name".to_string()));
        assert!(!schema.required.contains(&"count".to_string()));
    }

    #[test]
    fn test_common_schemas_compile() {
        let _ = disassemble_at_schema().to_json();
        let _ = get_function_schema().to_json();
        let _ = list_functions_schema().to_json();
        let _ = search_string_schema().to_json();
        let _ = compute_hash_schema().to_json();
        let _ = get_section_schema().to_json();
    }

    #[test]
    fn test_enum_field_validation() {
        let schema = SchemaBuilder::new()
            .enum_field("mode", "mode", vec!["read", "write"], true)
            .build();
        let ok = json!({"mode": "read"});
        assert!(validate(&schema, &ok).is_empty());
        let bad = json!({"mode": "execute"});
        let errs = validate(&schema, &bad);
        assert!(errs.iter().any(|e| matches!(e, SchemaValidationError::NotInEnum { .. })));
    }

    #[test]
    fn test_array_property_items() {
        let prop = SchemaProperty::array("addresses", SchemaProperty::integer("address"));
        let j = prop.to_json();
        assert_eq!(j["type"], "array");
        assert!(j["items"].is_object());
        assert_eq!(j["items"]["type"], "integer");
    }
}
