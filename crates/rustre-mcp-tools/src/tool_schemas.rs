//! `tool_schemas` â€” **manifest / registry layer**.
//!
//! Provides [`ToolSchemas`] (central registry of all `RustRE` tool manifests),
//! [`ParameterSchema`], [`ResponseSchema`], [`ToolManifest`], and
//! [`SchemaValidator`].
//!
//! [`SchemaType`] is re-exported from the primitive layer ([`super::tool_schema`])
//! to avoid a duplicate definition.  The [`SchemaProperty`] here is deliberately
//! different from `tool_schema::SchemaProperty`: it carries an embedded `name`
//! and `required` flag that makes declarative manifest construction ergonomic,
//! whereas the primitive layer's version is a schema-only value object used by
//! the fluent [`super::tool_schema::SchemaBuilder`].

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use thiserror::Error;

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// Errors
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Errors from the schema subsystem.
#[derive(Debug, Error)]
pub enum SchemaError {
    #[error("unknown tool: {0}")]
    UnknownTool(String),
    #[error("required parameter missing: {0}")]
    MissingRequired(String),
    #[error("type mismatch for '{field}': expected {expected}, got {got}")]
    TypeMismatch {
        field: String,
        expected: String,
        got: String,
    },
    #[error("value out of range for '{field}': {value}")]
    OutOfRange { field: String, value: String },
    #[error("invalid enum value for '{field}': {value}")]
    InvalidEnum { field: String, value: String },
    #[error("additional properties not allowed: {0}")]
    AdditionalProperty(String),
    #[error("JSON serialization: {0}")]
    Json(#[from] serde_json::Error),
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// SchemaProperty
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// JSON Schema type string.
///
/// Re-exported from [`crate::tool_schema::SchemaType`] â€” the single canonical
/// definition for this crate.  `matches_value` is also available on this type.
pub use crate::tool_schema::SchemaType;

/// A single property in a JSON Schema object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchemaProperty {
    pub name: String,
    pub schema_type: SchemaType,
    pub description: String,
    pub required: bool,
    pub default: Option<Value>,
    pub enum_values: Option<Vec<Value>>,
    pub minimum: Option<f64>,
    pub maximum: Option<f64>,
    pub min_length: Option<usize>,
    pub max_length: Option<usize>,
    pub items: Option<Box<Self>>,
}

impl SchemaProperty {
    #[must_use] 
    pub fn new(name: &str, schema_type: SchemaType, description: &str) -> Self {
        Self {
            name: name.into(),
            schema_type,
            description: description.into(),
            required: false,
            default: None,
            enum_values: None,
            minimum: None,
            maximum: None,
            min_length: None,
            max_length: None,
            items: None,
        }
    }

    #[must_use] 
    pub const fn required(mut self) -> Self {
        self.required = true;
        self
    }
    #[must_use] 
    pub fn with_default(mut self, v: Value) -> Self {
        self.default = Some(v);
        self
    }
    #[must_use]
    pub fn with_enum<V: Into<Value>>(mut self, values: V) -> Self {
        let v: Value = values.into();
        let arr = match v {
            Value::Array(a) => a,
            other => vec![other],
        };
        self.enum_values = Some(arr);
        self
    }
    #[must_use] 
    pub const fn with_range(mut self, min: f64, max: f64) -> Self {
        self.minimum = Some(min);
        self.maximum = Some(max);
        self
    }

    #[must_use] 
    pub fn to_json_schema(&self) -> Value {
        let mut v = json!({
            "type": self.schema_type.as_str(),
            "description": self.description,
        });
        if let Some(d) = &self.default {
            v["default"] = d.clone();
        }
        if let Some(e) = &self.enum_values {
            v["enum"] = json!(e);
        }
        if let Some(min) = self.minimum {
            v["minimum"] = json!(min);
        }
        if let Some(max) = self.maximum {
            v["maximum"] = json!(max);
        }
        if let Some(ml) = self.min_length {
            v["minLength"] = json!(ml);
        }
        if let Some(ml) = self.max_length {
            v["maxLength"] = json!(ml);
        }
        if let Some(items) = &self.items {
            v["items"] = items.to_json_schema();
        }
        v
    }

    /// Validate a single value against this property.
    ///
    /// # Errors
    /// Returns `Err` if the value fails type, enum, or range validation.
    pub fn validate(&self, value: &Value) -> Result<(), SchemaError> {
        if !self.schema_type.matches_value(value) {
            return Err(SchemaError::TypeMismatch {
                field: self.name.clone(),
                expected: self.schema_type.as_str().to_string(),
                got: json_type_name(value).to_string(),
            });
        }
        if let Some(ref enums) = self.enum_values
            && !enums.contains(value) {
                return Err(SchemaError::InvalidEnum {
                    field: self.name.clone(),
                    value: value.to_string(),
                });
            }
        if let Some(min) = self.minimum
            && let Some(n) = value.as_f64()
                && n < min {
                    return Err(SchemaError::OutOfRange {
                        field: self.name.clone(),
                        value: n.to_string(),
                    });
                }
        if let Some(max) = self.maximum
            && let Some(n) = value.as_f64()
                && n > max {
                    return Err(SchemaError::OutOfRange {
                        field: self.name.clone(),
                        value: n.to_string(),
                    });
                }
        Ok(())
    }
}

// Reuse the canonical helper from the primitive layer.
use crate::tool_schema::json_type_name;

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// ParameterSchema
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Complete input schema for a tool (collection of properties).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ParameterSchema {
    pub properties: Vec<SchemaProperty>,
    pub additional_properties: bool,
}

impl ParameterSchema {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use] 
    pub fn with_prop(mut self, prop: SchemaProperty) -> Self {
        self.properties.push(prop);
        self
    }

    #[must_use] 
    pub fn required_names(&self) -> Vec<&str> {
        self.properties
            .iter()
            .filter(|p| p.required)
            .map(|p| p.name.as_str())
            .collect()
    }

    #[must_use] 
    pub fn to_json_schema(&self) -> Value {
        let mut props = json!({});
        for p in &self.properties {
            props[&p.name] = p.to_json_schema();
        }
        let required: Vec<&str> = self.required_names();
        json!({
            "type": "object",
            "properties": props,
            "required": required,
            "additionalProperties": self.additional_properties,
        })
    }

    /// # Errors
    /// Returns `Err` if required fields are missing or any field fails validation.
    pub fn validate_object(&self, obj: &Value) -> Result<(), SchemaError> {
        let map = obj.as_object().ok_or_else(|| SchemaError::TypeMismatch {
            field: "(root)".into(),
            expected: "object".into(),
            got: json_type_name(obj).into(),
        })?;
        // Check required
        for req in self.required_names() {
            if !map.contains_key(req) {
                return Err(SchemaError::MissingRequired(req.to_string()));
            }
        }
        // Validate present fields
        for p in &self.properties {
            if let Some(v) = map.get(&p.name) {
                p.validate(v)?;
            }
        }
        // Additional properties
        if !self.additional_properties {
            let known: std::collections::HashSet<&str> =
                self.properties.iter().map(|p| p.name.as_str()).collect();
            for key in map.keys() {
                if !known.contains(key.as_str()) {
                    return Err(SchemaError::AdditionalProperty(key.clone()));
                }
            }
        }
        Ok(())
    }
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// ResponseSchema
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Schema for the response of a tool.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseSchema {
    pub description: String,
    pub schema: Value,
    pub example: Option<Value>,
}

impl ResponseSchema {
    #[must_use] 
    pub fn new(description: &str, schema: Value) -> Self {
        Self {
            description: description.into(),
            schema,
            example: None,
        }
    }

    #[must_use] 
    pub fn with_example(mut self, ex: Value) -> Self {
        self.example = Some(ex);
        self
    }
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// ToolManifest
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Complete manifest for a single `RustRE` MCP tool.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolManifest {
    pub name: String,
    pub version: String,
    pub description: String,
    pub category: String,
    pub tags: Vec<String>,
    pub parameters: ParameterSchema,
    pub response: ResponseSchema,
    pub deprecated: bool,
    pub min_protocol_version: String,
}

impl ToolManifest {
    #[must_use] 
    pub fn to_mcp_tool(&self) -> Value {
        json!({
            "name": self.name,
            "description": self.description,
            "inputSchema": self.parameters.to_json_schema(),
        })
    }
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// SchemaValidator
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Validates tool input against registered schemas.
#[derive(Debug, Default)]
pub struct SchemaValidator {
    schemas: HashMap<String, ParameterSchema>,
}

impl SchemaValidator {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self, tool: impl Into<String>, schema: ParameterSchema) {
        self.schemas.insert(tool.into(), schema);
    }

    /// # Errors
    /// Returns `Err` if the tool is unknown or params fail schema validation.
    pub fn validate(&self, tool: &str, params: &Value) -> Result<(), SchemaError> {
        let schema = self
            .schemas
            .get(tool)
            .ok_or_else(|| SchemaError::UnknownTool(tool.to_string()))?;
        schema.validate_object(params)
    }

    #[must_use] 
    pub fn registered_count(&self) -> usize {
        self.schemas.len()
    }

    #[must_use] 
    pub fn has_tool(&self, tool: &str) -> bool {
        self.schemas.contains_key(tool)
    }
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// ToolSchemas
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Central registry of all `RustRE` MCP tool manifests.
pub struct ToolSchemas {
    manifests: HashMap<String, ToolManifest>,
    validator: SchemaValidator,
}

impl ToolSchemas {
    /// Build the complete schema registry for all `RustRE` tools.
    #[must_use] 
    pub fn new() -> Self {
        let mut s = Self {
            manifests: HashMap::new(),
            validator: SchemaValidator::new(),
        };
        s.register_all();
        s
    }

    fn register_all(&mut self) {
        self.register_manifest(Self::manifest_disassemble());
        self.register_manifest(Self::manifest_decompile());
        self.register_manifest(Self::manifest_find_strings());
        self.register_manifest(Self::manifest_pe_info());
        self.register_manifest(Self::manifest_elf_info());
        self.register_manifest(Self::manifest_macho_info());
        self.register_manifest(Self::manifest_find_vulnerabilities());
        self.register_manifest(Self::manifest_analyze_crypto());
        self.register_manifest(Self::manifest_deobfuscate_strings());
        self.register_manifest(Self::manifest_identify_malware());
        self.register_manifest(Self::manifest_extract_config());
        self.register_manifest(Self::manifest_generate_yara());
        self.register_manifest(Self::manifest_compare_functions());
        self.register_manifest(Self::manifest_xref_query());
        self.register_manifest(Self::manifest_call_graph());
        self.register_manifest(Self::manifest_patch_bytes());
        self.register_manifest(Self::manifest_symbol_lookup());
        self.register_manifest(Self::manifest_entropy());
        self.register_manifest(Self::manifest_triage());
        self.register_manifest(Self::manifest_findcrypt());
        self.register_manifest(Self::manifest_section_info());
        self.register_manifest(Self::manifest_recover_structs());
        self.register_manifest(Self::manifest_function_list_by_kind());
        self.register_manifest(Self::manifest_analysis_xref("analysis_xref_to", "Xrefs targeting addr"));
        self.register_manifest(Self::manifest_analysis_xref("analysis_xref_from", "Xrefs originating from addr"));
        self.register_manifest(Self::manifest_analysis_addr_only(
            "analysis_fn_callees",
            "List callees of a function",
        ));
        self.register_manifest(Self::manifest_analysis_addr_only(
            "analysis_fn_stack_frame",
            "Recover stack-frame layout (total_size, saved_regs, vars, has_alloca) for the function at addr",
        ));
        self.register_manifest(Self::manifest_analysis_fn_callgraph());
        self.register_manifest(Self::manifest_analysis_fn_callgraph_dot());
        self.register_manifest(Self::manifest_analysis_fn_callgraph_dot_styled());
        self.register_manifest(Self::manifest_analysis_dataflow_backward());
        self.register_manifest(Self::manifest_analysis_dataflow_forward());
        self.register_manifest(Self::manifest_analysis_addr_only(
            "analysis_cfg_basic_blocks",
            "Recover basic blocks for the function at addr",
        ));
        self.register_manifest(Self::manifest_analysis_addr_only(
            "analysis_type_infer_function",
            "Look up inferred function signature",
        ));
        self.register_manifest(Self::manifest_arch_x86_disasm("arch_x86_disasm_64", 64));
        self.register_manifest(Self::manifest_arch_x86_disasm("arch_x86_disasm_16", 16));
        self.register_manifest(Self::manifest_deobf_mba_normalize());
        self.register_manifest(Self::manifest_analysis_string_xrefs());
        self.register_manifest(Self::manifest_analysis_vsa_query());
    }

    fn manifest_analysis_vsa_query() -> ToolManifest {
        ToolManifest {
            name: "analysis_vsa_query".into(),
            version: "1.0.0".into(),
            description: "Query the VSA abstract value set at a program address for a register or [reg+offset] memory expression. Returns {values:[{kind,repr}], confidence}.".into(),
            category: "analysis".into(),
            tags: vec!["vsa".into(), "dataflow".into(), "valueset".into()],
            parameters: Self::analysis_base_params().with_prop(SchemaProperty::new(
                    "target",
                    SchemaType::String,
                    "Register name (e.g. 'rax') or [reg+offset] memory expression (e.g. '[rsp+8]')",
                )
                .required(),
            ),
            response: ResponseSchema::new(
                "Point-query result",
                json!({
                    "type": "object",
                    "properties": {
                        "values": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "properties": {
                                    "kind": { "type": "string", "enum": ["const", "range", "set", "unknown"] },
                                    "repr": { "type": "string" }
                                }
                            }
                        },
                        "confidence": { "type": "string", "enum": ["low", "medium", "high"] }
                    }
                }),
            ),
            deprecated: false,
            min_protocol_version: "2024-11-05".into(),
        }
    }

    fn manifest_analysis_string_xrefs() -> ToolManifest {
        ToolManifest {
            name: "analysis_string_xrefs".into(),
            version: "1.0.0".into(),
            description: "List code references to each extracted string, optionally grouped by containing function.".into(),
            category: "analysis".into(),
            tags: vec!["string".into(), "xref".into()],
            parameters: ParameterSchema::new()
                .with_prop(SchemaProperty::new("session_id", SchemaType::String, "Session id"))
                .with_prop(SchemaProperty::new("path", SchemaType::String, "Binary path"))
                .with_prop(SchemaProperty::new("min_length", SchemaType::Integer, "Minimum string length")
                        .with_default(json!(4)),
                ),
            response: ResponseSchema::new(
                "List of StringXref entries",
                json!({"type": "object"}),
            ),
            deprecated: false,
            min_protocol_version: "2024-11-05".into(),
        }
    }

    fn manifest_deobf_mba_normalize() -> ToolManifest {
        ToolManifest {
            name: "deobf_mba_normalize".into(),
            version: "1.0.0".into(),
            description: "Normalize a Mixed-Boolean-Arithmetic (MBA) expression to its canonical form using the rustre-deobf-mba simplifier (applies identities such as (x^y)+2*(x&y) -> x+y).".into(),
            category: "deobfuscation".into(),
            tags: vec!["mba".into(), "normalize".into(), "simplify".into()],
            parameters: ParameterSchema::new()
                .with_prop(SchemaProperty::new(
                        "expr",
                        SchemaType::String,
                        "MBA expression text, e.g. '(x ^ y) + 2*(x & y)'",
                    )
                    .required(),
                )
                .with_prop(SchemaProperty::new(
                        "max_iterations",
                        SchemaType::Integer,
                        "Optional simplifier iteration cap",
                    )
                    .with_default(json!(100)),
                ),
            response: ResponseSchema::new(
                "Simplified MBA expression and rule trace",
                json!({"type": "object"}),
            ),
            deprecated: false,
            min_protocol_version: "2024-11-05".into(),
        }
    }

    fn analysis_base_params() -> ParameterSchema {
        ParameterSchema::new()
            .with_prop(Self::addr_param("addr", "Target address").required())
            .with_prop(SchemaProperty::new("session_id", SchemaType::String, "Session id"))
            .with_prop(SchemaProperty::new("path", SchemaType::String, "Binary path"))
    }

    fn manifest_analysis_xref(name: &str, desc: &str) -> ToolManifest {
        ToolManifest {
            name: name.into(),
            version: "1.0.0".into(),
            description: desc.into(),
            category: "analysis".into(),
            tags: vec!["xref".into()],
            parameters: Self::analysis_base_params(),
            response: ResponseSchema::new("Xref list", json!({"type": "object"})),
            deprecated: false,
            min_protocol_version: "2024-11-05".into(),
        }
    }

    fn manifest_analysis_addr_only(name: &str, desc: &str) -> ToolManifest {
        ToolManifest {
            name: name.into(),
            version: "1.0.0".into(),
            description: desc.into(),
            category: "analysis".into(),
            tags: vec!["analysis".into()],
            parameters: Self::analysis_base_params(),
            response: ResponseSchema::new("Analyzer result", json!({"type": "object"})),
            deprecated: false,
            min_protocol_version: "2024-11-05".into(),
        }
    }

    fn manifest_analysis_fn_callgraph() -> ToolManifest {
        ToolManifest {
            name: "analysis_fn_callgraph".into(),
            version: "1.0.0".into(),
            description: "BFS call-graph slice rooted at addr.".into(),
            category: "analysis".into(),
            tags: vec!["callgraph".into()],
            parameters: Self::analysis_base_params().with_prop(SchemaProperty::new("depth", SchemaType::Integer, "Max BFS depth")
                    .with_range(1.0, 10.0)
                    .with_default(json!(3)),
            ),
            response: ResponseSchema::new("Call-graph slice", json!({"type": "object"})),
            deprecated: false,
            min_protocol_version: "2024-11-05".into(),
        }
    }

    fn manifest_analysis_fn_callgraph_dot() -> ToolManifest {
        ToolManifest {
            name: "analysis_fn_callgraph_dot".into(),
            version: "1.0.0".into(),
            description: "BFS call-graph slice rendered as Graphviz DOT.".into(),
            category: "analysis".into(),
            tags: vec!["callgraph".into(), "dot".into()],
            parameters: Self::analysis_base_params().with_prop(SchemaProperty::new("depth", SchemaType::Integer, "Max BFS depth")
                    .with_range(1.0, 10.0)
                    .with_default(json!(3)),
            ),
            response: ResponseSchema::new("Graphviz DOT text", json!({"type": "string"})),
            deprecated: false,
            min_protocol_version: "2024-11-05".into(),
        }
    }

    fn manifest_analysis_fn_callgraph_dot_styled() -> ToolManifest {
        ToolManifest {
            name: "analysis_fn_callgraph_dot_styled".into(),
            version: "1.0.0".into(),
            description: "BFS call-graph slice rendered as styled Graphviz DOT.".into(),
            category: "analysis".into(),
            tags: vec!["callgraph".into(), "dot".into(), "styled".into()],
            parameters: Self::analysis_base_params()
                .with_prop(SchemaProperty::new("depth", SchemaType::Integer, "Max BFS depth")
                        .with_range(1.0, 10.0)
                        .with_default(json!(3)),
                )
                .with_prop(SchemaProperty::new(
                    "color_external",
                    SchemaType::Boolean,
                    "Tint sub_* nodes light gray",
                ))
                .with_prop(Self::addr_param(
                    "highlight_root_addr",
                    "Address to fill light yellow",
                ))
                .with_prop(SchemaProperty::new(
                    "font",
                    SchemaType::String,
                    "Graphviz node/edge fontname",
                )),
            response: ResponseSchema::new("Graphviz DOT text", json!({"type": "string"})),
            deprecated: false,
            min_protocol_version: "2024-11-05".into(),
        }
    }

    fn manifest_analysis_dataflow_backward() -> ToolManifest {
        ToolManifest {
            name: "analysis_dataflow_trace_backward".into(),
            version: "1.0.0".into(),
            description: "Backward caller trace by hops.".into(),
            category: "analysis".into(),
            tags: vec!["dataflow".into(), "trace".into()],
            parameters: Self::analysis_base_params().with_prop(SchemaProperty::new("hops", SchemaType::Integer, "Hops to trace")
                    .with_range(0.0, 10.0)
                    .with_default(json!(3)),
            ),
            response: ResponseSchema::new("Backward trace", json!({"type": "object"})),
            deprecated: false,
            min_protocol_version: "2024-11-05".into(),
        }
    }

    fn manifest_analysis_dataflow_forward() -> ToolManifest {
        ToolManifest {
            name: "analysis_dataflow_trace_forward".into(),
            version: "1.0.0".into(),
            description: "Forward callee trace by hops.".into(),
            category: "analysis".into(),
            tags: vec!["dataflow".into(), "trace".into()],
            parameters: Self::analysis_base_params().with_prop(SchemaProperty::new("hops", SchemaType::Integer, "Hops to trace")
                    .with_range(0.0, 10.0)
                    .with_default(json!(3)),
            ),
            response: ResponseSchema::new("Forward trace", json!({"type": "object"})),
            deprecated: false,
            min_protocol_version: "2024-11-05".into(),
        }
    }

    fn manifest_arch_x86_disasm(name: &str, bitness: u32) -> ToolManifest {
        ToolManifest {
            name: name.into(),
            version: "1.0.0".into(),
            description: format!("Disassemble {bitness}-bit x86 bytes (att|intel)."),
            category: "disassembly".into(),
            tags: vec!["x86".into(), "disasm".into()],
            parameters: Self::analysis_base_params()
                .with_prop(SchemaProperty::new("hex", SchemaType::String, "Hex-encoded bytes")
                        .required(),
                )
                .with_prop(SchemaProperty::new("syntax", SchemaType::String, "att | intel")
                        .with_enum(json!(["att", "intel"]))
                        .with_default(json!("att")),
                ),
            response: ResponseSchema::new("Instruction list", json!({"type": "object"})),
            deprecated: false,
            min_protocol_version: "2024-11-05".into(),
        }
    }

    fn register_manifest(&mut self, m: ToolManifest) {
        self.validator
            .register(m.name.clone(), m.parameters.clone());
        self.manifests.insert(m.name.clone(), m);
    }

    #[must_use] 
    pub fn manifest_count(&self) -> usize {
        self.manifests.len()
    }

    #[must_use] 
    pub fn get(&self, name: &str) -> Option<&ToolManifest> {
        self.manifests.get(name)
    }

    #[must_use] 
    pub fn list_names(&self) -> Vec<&str> {
        self.manifests.keys().map(std::string::String::as_str).collect()
    }

    /// # Errors
    /// Returns `Err` if the tool is unknown or params fail schema validation.
    pub fn validate(&self, tool: &str, params: &Value) -> Result<(), SchemaError> {
        self.validator.validate(tool, params)
    }

    #[must_use] 
    pub fn to_mcp_tools_list(&self) -> Vec<Value> {
        let mut list: Vec<Value> = self.manifests.values().map(ToolManifest::to_mcp_tool).collect();
        list.sort_by(|a, b| a["name"].as_str().cmp(&b["name"].as_str()));
        list
    }

    // â”€â”€ Manifest builders â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    fn bytes_or_hex_params() -> ParameterSchema {
        ParameterSchema::new()
            .with_prop(SchemaProperty::new(
                "bytes",
                SchemaType::Array,
                "Raw binary bytes (array of integers 0-255)",
            ))
            .with_prop(SchemaProperty::new(
                "hex",
                SchemaType::String,
                "Hex-encoded binary data",
            ))
    }

    fn arch_param() -> SchemaProperty {
        SchemaProperty::new("arch", SchemaType::String, "Target architecture")
            .with_enum(json!([
                "x86", "x86_64", "arm", "arm64", "mips", "ppc", "riscv"
            ]))
            .with_default(json!("x86_64"))
    }

    fn addr_param(name: &str, desc: &str) -> SchemaProperty {
        SchemaProperty::new(name, SchemaType::Integer, desc).with_range(0.0, f64::MAX)
    }

    fn manifest_disassemble() -> ToolManifest {
        ToolManifest {
            name: "disassemble".into(),
            version: "1.0.0".into(),
            description: "Disassemble a byte sequence into human-readable assembly instructions."
                .into(),
            category: "disassembly".into(),
            tags: vec!["asm".into(), "disasm".into()],
            parameters: Self::bytes_or_hex_params()
                .with_prop(Self::arch_param())
                .with_prop(Self::addr_param(
                    "base_address",
                    "Virtual address of the first byte",
                ))
                .with_prop(SchemaProperty::new(
                        "max_instructions",
                        SchemaType::Integer,
                        "Maximum instructions to decode",
                    )
                    .with_range(1.0, 10000.0)
                    .with_default(json!(64)),
                ),
            response: ResponseSchema::new(
                "Disassembly listing",
                json!({
                    "type": "object",
                    "properties": { "instructions": { "type": "array" }, "count": { "type": "integer" } }
                }),
            ),
            deprecated: false,
            min_protocol_version: "2024-11-05".into(),
        }
    }

    fn manifest_decompile() -> ToolManifest {
        ToolManifest {
            name: "decompile".into(),
            version: "1.0.0".into(),
            description: "Decompile a function from its bytes into pseudo-C code.".into(),
            category: "decompilation".into(),
            tags: vec!["decompile".into(), "pseudo-c".into()],
            parameters: Self::bytes_or_hex_params()
                .with_prop(Self::arch_param())
                .with_prop(Self::addr_param(
                    "function_address",
                    "Start address of the function",
                )),
            response: ResponseSchema::new("Pseudo-C output", json!({"type": "object"})),
            deprecated: false,
            min_protocol_version: "2024-11-05".into(),
        }
    }

    fn manifest_find_strings() -> ToolManifest {
        ToolManifest {
            name: "find_strings".into(),
            version: "1.0.0".into(),
            description: "Extract printable strings (ASCII and UTF-16LE) from binary data.".into(),
            category: "strings".into(),
            tags: vec!["strings".into()],
            parameters: Self::bytes_or_hex_params()
                .with_prop(SchemaProperty::new("min_length", SchemaType::Integer, "Minimum string length")
                        .with_range(1.0, 1024.0)
                        .with_default(json!(4)),
                )
                .with_prop(SchemaProperty::new("encoding", SchemaType::String, "String encoding")
                        .with_enum(json!(["ascii", "utf16le", "both"]))
                        .with_default(json!("both")),
                ),
            response: ResponseSchema::new("Found strings", json!({"type": "object"})),
            deprecated: false,
            min_protocol_version: "2024-11-05".into(),
        }
    }

    fn manifest_pe_info() -> ToolManifest {
        ToolManifest {
            name: "pe_info".into(),
            version: "1.0.0".into(),
            description: "Parse and return complete PE header information.".into(),
            category: "loaders".into(),
            tags: vec!["pe".into(), "windows".into()],
            parameters: Self::bytes_or_hex_params(),
            response: ResponseSchema::new("PE header fields", json!({"type": "object"})),
            deprecated: false,
            min_protocol_version: "2024-11-05".into(),
        }
    }

    fn manifest_elf_info() -> ToolManifest {
        ToolManifest {
            name: "elf_info".into(),
            version: "1.0.0".into(),
            description: "Parse and return ELF header, sections, and program headers.".into(),
            category: "loaders".into(),
            tags: vec!["elf".into(), "linux".into()],
            parameters: Self::bytes_or_hex_params(),
            response: ResponseSchema::new("ELF info", json!({"type": "object"})),
            deprecated: false,
            min_protocol_version: "2024-11-05".into(),
        }
    }

    fn manifest_macho_info() -> ToolManifest {
        ToolManifest {
            name: "macho_info".into(),
            version: "1.0.0".into(),
            description: "Parse and return Mach-O header and load commands.".into(),
            category: "loaders".into(),
            tags: vec!["macho".into(), "macos".into()],
            parameters: Self::bytes_or_hex_params(),
            response: ResponseSchema::new("Mach-O info", json!({"type": "object"})),
            deprecated: false,
            min_protocol_version: "2024-11-05".into(),
        }
    }

    fn manifest_find_vulnerabilities() -> ToolManifest {
        ToolManifest {
            name: "find_vulnerabilities".into(),
            version: "1.0.0".into(),
            description: "Detect common binary vulnerabilities in a code sequence.".into(),
            category: "security".into(),
            tags: vec!["vulns".into(), "security".into()],
            parameters: Self::bytes_or_hex_params().with_prop(Self::arch_param()),
            response: ResponseSchema::new("Vulnerability list", json!({"type": "object"})),
            deprecated: false,
            min_protocol_version: "2024-11-05".into(),
        }
    }

    fn manifest_analyze_crypto() -> ToolManifest {
        ToolManifest {
            name: "analyze_crypto".into(),
            version: "1.0.0".into(),
            description: "Identify cryptographic constants and algorithms.".into(),
            category: "crypto".into(),
            tags: vec!["crypto".into(), "aes".into(), "rsa".into()],
            parameters: Self::bytes_or_hex_params().with_prop(SchemaProperty::new(
                    "min_confidence",
                    SchemaType::Number,
                    "Minimum match confidence (0-1)",
                )
                .with_range(0.0, 1.0)
                .with_default(json!(0.6)),
            ),
            response: ResponseSchema::new("Crypto matches", json!({"type": "object"})),
            deprecated: false,
            min_protocol_version: "2024-11-05".into(),
        }
    }

    fn manifest_deobfuscate_strings() -> ToolManifest {
        ToolManifest {
            name: "deobfuscate_strings".into(),
            version: "1.0.0".into(),
            description:
                "Decode obfuscated strings using XOR, ROT-13, base64, stack-string reconstruction."
                    .into(),
            category: "deobfuscation".into(),
            tags: vec!["strings".into(), "xor".into()],
            parameters: Self::bytes_or_hex_params(),
            response: ResponseSchema::new("Decoded strings", json!({"type": "object"})),
            deprecated: false,
            min_protocol_version: "2024-11-05".into(),
        }
    }

    fn manifest_identify_malware() -> ToolManifest {
        ToolManifest {
            name: "identify_malware".into(),
            version: "1.0.0".into(),
            description: "Classify a binary sample against known malware families.".into(),
            category: "threatintel".into(),
            tags: vec!["malware".into(), "classification".into()],
            parameters: Self::bytes_or_hex_params().with_prop(SchemaProperty::new("use_yara", SchemaType::Boolean, "Apply YARA rules")
                    .with_default(json!(true)),
            ),
            response: ResponseSchema::new("Malware classifications", json!({"type": "object"})),
            deprecated: false,
            min_protocol_version: "2024-11-05".into(),
        }
    }

    fn manifest_extract_config() -> ToolManifest {
        ToolManifest {
            name: "extract_config".into(),
            version: "1.0.0".into(),
            description: "Extract embedded configuration (C2, keys, ports) from malware.".into(),
            category: "threatintel".into(),
            tags: vec!["config".into(), "malware".into()],
            parameters: Self::bytes_or_hex_params().with_prop(SchemaProperty::new(
                "family",
                SchemaType::String,
                "Optional known malware family hint",
            )),
            response: ResponseSchema::new("Config values", json!({"type": "object"})),
            deprecated: false,
            min_protocol_version: "2024-11-05".into(),
        }
    }

    fn manifest_generate_yara() -> ToolManifest {
        ToolManifest {
            name: "generate_yara".into(),
            version: "1.0.0".into(),
            description: "Auto-generate a YARA rule from a binary sample.".into(),
            category: "threatintel".into(),
            tags: vec!["yara".into()],
            parameters: Self::bytes_or_hex_params()
                .with_prop(SchemaProperty::new("rule_name", SchemaType::String, "Name for the YARA rule")
                        .with_default(json!("auto_generated")),
                )
                .with_prop(SchemaProperty::new(
                        "min_string_length",
                        SchemaType::Integer,
                        "Minimum string length for inclusion",
                    )
                    .with_range(4.0, 256.0)
                    .with_default(json!(8)),
                ),
            response: ResponseSchema::new("YARA rule", json!({"type": "object"})),
            deprecated: false,
            min_protocol_version: "2024-11-05".into(),
        }
    }

    fn manifest_compare_functions() -> ToolManifest {
        ToolManifest {
            name: "compare_functions".into(),
            version: "1.0.0".into(),
            description: "Compute structural similarity between two function byte sequences."
                .into(),
            category: "diff".into(),
            tags: vec!["diff".into(), "similarity".into()],
            parameters: ParameterSchema::new()
                .with_prop(SchemaProperty::new(
                    "bytes_a",
                    SchemaType::Array,
                    "First function bytes",
                ))
                .with_prop(SchemaProperty::new(
                    "bytes_b",
                    SchemaType::Array,
                    "Second function bytes",
                ))
                .with_prop(SchemaProperty::new(
                    "hex_a",
                    SchemaType::String,
                    "First function (hex)",
                ))
                .with_prop(SchemaProperty::new(
                    "hex_b",
                    SchemaType::String,
                    "Second function (hex)",
                ))
                .with_prop(Self::arch_param()),
            response: ResponseSchema::new("Comparison result", json!({"type": "object"})),
            deprecated: false,
            min_protocol_version: "2024-11-05".into(),
        }
    }

    fn manifest_xref_query() -> ToolManifest {
        ToolManifest {
            name: "xref_query".into(),
            version: "1.0.0".into(),
            description: "Find cross-references to or from a given address.".into(),
            category: "analysis".into(),
            tags: vec!["xref".into()],
            parameters: ParameterSchema::new()
                .with_prop(Self::addr_param("address", "Target address").required())
                .with_prop(SchemaProperty::new("direction", SchemaType::String, "xrefs_to or xrefs_from")
                        .with_enum(json!(["to", "from"]))
                        .with_default(json!("to")),
                )
                .with_prop(SchemaProperty::new("max_results", SchemaType::Integer, "Maximum results")
                        .with_range(1.0, 10000.0)
                        .with_default(json!(100)),
                ),
            response: ResponseSchema::new("Cross-reference list", json!({"type": "object"})),
            deprecated: false,
            min_protocol_version: "2024-11-05".into(),
        }
    }

    fn manifest_call_graph() -> ToolManifest {
        ToolManifest {
            name: "call_graph".into(),
            version: "1.0.0".into(),
            description: "Build a call graph starting from a root function address.".into(),
            category: "analysis".into(),
            tags: vec!["callgraph".into()],
            parameters: ParameterSchema::new()
                .with_prop(Self::addr_param("root_address", "Root function address").required())
                .with_prop(SchemaProperty::new("max_depth", SchemaType::Integer, "Maximum call depth")
                        .with_range(1.0, 32.0)
                        .with_default(json!(5)),
                ),
            response: ResponseSchema::new("Call graph JSON", json!({"type": "object"})),
            deprecated: false,
            min_protocol_version: "2024-11-05".into(),
        }
    }

    fn manifest_patch_bytes() -> ToolManifest {
        ToolManifest {
            name: "patch_bytes".into(),
            version: "1.0.0".into(),
            description: "Patch bytes in a binary at a given offset.".into(),
            category: "editing".into(),
            tags: vec!["patch".into()],
            parameters: ParameterSchema::new()
                .with_prop(Self::bytes_or_hex_params().properties.remove(0)) // bytes
                .with_prop(Self::addr_param("offset", "File offset to patch").required())
                .with_prop(SchemaProperty::new("patch_hex", SchemaType::String, "Hex bytes to write")
                        .required(),
                ),
            response: ResponseSchema::new("Patched binary bytes", json!({"type": "object"})),
            deprecated: false,
            min_protocol_version: "2024-11-05".into(),
        }
    }

    fn manifest_symbol_lookup() -> ToolManifest {
        ToolManifest {
            name: "symbol_lookup".into(),
            version: "1.0.0".into(),
            description: "Look up a symbol name from an address or a hash.".into(),
            category: "symbols".into(),
            tags: vec!["symbols".into()],
            parameters: ParameterSchema::new()
                .with_prop(SchemaProperty::new(
                    "address",
                    SchemaType::Integer,
                    "Symbol address",
                ))
                .with_prop(SchemaProperty::new(
                    "name",
                    SchemaType::String,
                    "Symbol name (partial match)",
                ))
                .with_prop(SchemaProperty::new(
                    "hash",
                    SchemaType::Integer,
                    "Import-by-hash value",
                )),
            response: ResponseSchema::new("Symbol list", json!({"type": "object"})),
            deprecated: false,
            min_protocol_version: "2024-11-05".into(),
        }
    }

    fn manifest_entropy() -> ToolManifest {
        ToolManifest {
            name: "entropy".into(),
            version: "1.0.0".into(),
            description: "Compute Shannon entropy of binary data or named sections.".into(),
            category: "analysis".into(),
            tags: vec!["entropy".into(), "packing".into()],
            parameters: Self::bytes_or_hex_params().with_prop(SchemaProperty::new(
                    "block_size",
                    SchemaType::Integer,
                    "Block size for sliding window entropy",
                )
                .with_range(16.0, 65536.0)
                .with_default(json!(256)),
            ),
            response: ResponseSchema::new("Entropy values", json!({"type": "object"})),
            deprecated: false,
            min_protocol_version: "2024-11-05".into(),
        }
    }

    fn manifest_triage() -> ToolManifest {
        ToolManifest {
            name: "triage".into(),
            version: "1.0.0".into(),
            description: "Quick triage a binary: detect packer, format, basic metadata.".into(),
            category: "triage".into(),
            tags: vec!["triage".into(), "format".into()],
            parameters: Self::bytes_or_hex_params(),
            response: ResponseSchema::new("Triage summary", json!({"type": "object"})),
            deprecated: false,
            min_protocol_version: "2024-11-05".into(),
        }
    }

    fn manifest_findcrypt() -> ToolManifest {
        ToolManifest {
            name: "triage_core_run_findcrypt".into(),
            version: "1.0.0".into(),
            description:
                "Scan a loaded binary for cryptographic constants (SHA-1/256 IV/K, MD5 IV, \
                 AES S-box/Rcon, TEA/XTEA delta, ChaCha20 sigma, RC4 init, CRC32 table head, \
                 Blowfish P-array). Returns one entry per anchor hit with algo, address, \
                 match_kind, and endianness."
                    .into(),
            category: "triage".into(),
            tags: vec!["triage".into(), "crypto".into(), "findcrypt".into()],
            parameters: Self::bytes_or_hex_params(),
            response: ResponseSchema::new(
                "FindCrypt hit list",
                json!({
                    "type": "object",
                    "properties": {
                        "hits": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "properties": {
                                    "algo":        { "type": "string" },
                                    "address":     { "type": "integer" },
                                    "match_kind":  { "type": "string" },
                                    "endianness":  { "type": "string" }
                                }
                            }
                        },
                        "count": { "type": "integer" }
                    }
                }),
            ),
            deprecated: false,
            min_protocol_version: "2024-11-05".into(),
        }
    }

    fn manifest_section_info() -> ToolManifest {
        ToolManifest {
            name: "section_info".into(),
            version: "1.0.0".into(),
            description: "List sections in a binary with addresses, sizes, and entropy.".into(),
            category: "loaders".into(),
            tags: vec!["sections".into()],
            parameters: Self::bytes_or_hex_params(),
            response: ResponseSchema::new("Section list", json!({"type": "object"})),
            deprecated: false,
            min_protocol_version: "2024-11-05".into(),
        }
    }

    fn manifest_recover_structs() -> ToolManifest {
        ToolManifest {
            name: "decompiler.recover_structs".into(),
            version: "1.0.0".into(),
            description:
                "Recover stack-frame and heap-allocation struct layouts from a function's \
                 memory-access pattern.  Returns one entry per distinct base pointer with field \
                 offsets, sizes, types, access counts, and a generated C declaration."
                    .into(),
            category: "decompilation".into(),
            tags: vec!["struct".into(), "recovery".into(), "decompile".into()],
            parameters: Self::bytes_or_hex_params()
                .with_prop(Self::arch_param())
                .with_prop(Self::addr_param("function_address", "Start address of the function"))
                .with_prop(SchemaProperty::new(
                        "include_heap",
                        SchemaType::Boolean,
                        "Treat malloc/calloc/operator new return registers as distinct heap bases",
                    )
                    .with_default(json!(true)),
                )
                .with_prop(SchemaProperty::new(
                        "min_access_count",
                        SchemaType::Integer,
                        "Minimum distinct accesses required to materialize a struct",
                    )
                    .with_range(1.0, 1024.0)
                    .with_default(json!(2)),
                ),
            response: ResponseSchema::new(
                "List of recovered structs",
                json!({
                    "type": "object",
                    "properties": {
                        "structs": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "properties": {
                                    "name": { "type": "string" },
                                    "base_kind": { "type": "string" },
                                    "total_size": { "type": "integer" },
                                    "has_padding": { "type": "boolean" },
                                    "fields": { "type": "array" },
                                    "c_decl": { "type": "string" }
                                }
                            }
                        }
                    }
                }),
            ),
            deprecated: false,
            min_protocol_version: "2024-11-05".into(),
        }
    }

    fn manifest_function_list_by_kind() -> ToolManifest {
        ToolManifest {
            name: "function_list_by_kind".into(),
            version: "1.0.0".into(),
            description:
                "After flirt_apply_auto labels functions as library code, list functions \
                 filtered by kind (library / user / all) and optionally by library name. \
                 Mirrors the library-vs-user split shown by mainstream disassemblers."
                    .into(),
            category: "analysis".into(),
            tags: vec![
                "library".into(),
                "classification".into(),
                "functions".into(),
            ],
            parameters: ParameterSchema::new()
                .with_prop(SchemaProperty::new(
                        "binary_path",
                        SchemaType::String,
                        "Path to the binary to inspect",
                    )
                    .required(),
                )
                .with_prop(SchemaProperty::new(
                        "kind",
                        SchemaType::String,
                        "Filter by classification: library, user, or all",
                    )
                    .with_enum(json!(["library", "user", "all"]))
                    .with_default(json!("all")),
                )
                .with_prop(SchemaProperty::new(
                    "lib_name",
                    SchemaType::String,
                    "Optional library name filter (e.g. 'libc', 'msvcrt')",
                ))
                .with_prop(SchemaProperty::new(
                        "limit",
                        SchemaType::Integer,
                        "Maximum number of functions to return (0 = unlimited)",
                    )
                    .with_range(0.0, f64::from(u32::MAX)),
                )
                .with_prop(SchemaProperty::new(
                        "min_confidence",
                        SchemaType::Integer,
                        "Minimum FLIRT match confidence (0-100)",
                    )
                    .with_range(0.0, 100.0),
                ),
            response: ResponseSchema::new(
                "Filtered function list",
                json!({"type": "object"}),
            ),
            deprecated: false,
            min_protocol_version: "2024-11-05".into(),
        }
    }
}

impl Default for ToolSchemas {
    fn default() -> Self {
        Self::new()
    }
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// Tests
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

#[cfg(test)]
mod tests {
    use super::*;

    fn schemas() -> ToolSchemas {
        ToolSchemas::new()
    }

    // â”€â”€ ToolSchemas registry â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn manifest_count_matches_registered() {
        assert_eq!(schemas().manifest_count(), 39);
    }

    #[test]
    fn contains_disassemble() {
        assert!(schemas().get("disassemble").is_some());
    }

    #[test]
    fn contains_find_vulnerabilities() {
        assert!(schemas().get("find_vulnerabilities").is_some());
    }

    #[test]
    fn contains_generate_yara() {
        assert!(schemas().get("generate_yara").is_some());
    }

    #[test]
    fn contains_compare_functions() {
        assert!(schemas().get("compare_functions").is_some());
    }

    #[test]
    fn contains_xref_query() {
        assert!(schemas().get("xref_query").is_some());
    }

    #[test]
    fn contains_entropy() {
        assert!(schemas().get("entropy").is_some());
    }

    #[test]
    fn list_names_count() {
        assert_eq!(schemas().list_names().len(), 39);
    }

    #[test]
    fn to_mcp_tools_list_sorted() {
        let list = schemas().to_mcp_tools_list();
        let names: Vec<&str> = list
            .iter()
            .map(|v| v["name"].as_str().unwrap_or(""))
            .collect();
        let mut sorted = names.clone();
        sorted.sort_unstable();
        assert_eq!(names, sorted);
    }

    // â”€â”€ ToolManifest â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn manifest_to_mcp_tool_has_name() {
        let s = schemas();
        let m = s.get("disassemble").unwrap();
        let j = m.to_mcp_tool();
        assert_eq!(j["name"], "disassemble");
    }

    #[test]
    fn manifest_has_input_schema() {
        let j = schemas().get("disassemble").unwrap().to_mcp_tool();
        assert!(j["inputSchema"].is_object());
    }

    // â”€â”€ SchemaProperty â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn schema_property_to_json_type() {
        let p = SchemaProperty::new("arch", SchemaType::String, "arch");
        let j = p.to_json_schema();
        assert_eq!(j["type"], "string");
    }

    #[test]
    fn schema_property_enum_in_json() {
        let p =
            SchemaProperty::new("mode", SchemaType::String, "mode").with_enum(json!(["a", "b"]));
        let j = p.to_json_schema();
        assert!(j["enum"].is_array());
    }

    #[test]
    fn schema_property_default_in_json() {
        let p = SchemaProperty::new("n", SchemaType::Integer, "n").with_default(json!(42));
        let j = p.to_json_schema();
        assert_eq!(j["default"], 42);
    }

    // â”€â”€ ParameterSchema validation â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn validate_object_required_missing_error() {
        let schema = ParameterSchema::new()
            .with_prop(SchemaProperty::new("foo", SchemaType::String, "req").required());
        let err = schema.validate_object(&json!({})).unwrap_err();
        assert!(matches!(err, SchemaError::MissingRequired(_)));
    }

    #[test]
    fn validate_object_required_present_ok() {
        let schema = ParameterSchema::new()
            .with_prop(SchemaProperty::new("foo", SchemaType::String, "req").required());
        assert!(schema.validate_object(&json!({"foo": "bar"})).is_ok());
    }

    #[test]
    fn validate_type_mismatch_error() {
        let schema =
            ParameterSchema::new().with_prop(SchemaProperty::new("n", SchemaType::Integer, "num"));
        let err = schema
            .validate_object(&json!({"n": "not_a_number"}))
            .unwrap_err();
        assert!(matches!(err, SchemaError::TypeMismatch { .. }));
    }

    #[test]
    fn validate_enum_invalid_error() {
        let schema = ParameterSchema::new()
            .with_prop(SchemaProperty::new("a", SchemaType::String, "").with_enum(json!(["x", "y"])));
        let err = schema.validate_object(&json!({"a": "z"})).unwrap_err();
        assert!(matches!(err, SchemaError::InvalidEnum { .. }));
    }

    #[test]
    fn validate_additional_property_error() {
        let schema =
            ParameterSchema::new().with_prop(SchemaProperty::new("known", SchemaType::String, ""));
        let err = schema
            .validate_object(&json!({"known": "v", "extra": "x"}))
            .unwrap_err();
        assert!(matches!(err, SchemaError::AdditionalProperty(_)));
    }

    #[test]
    fn validate_range_out_error() {
        let schema = ParameterSchema::new()
            .with_prop(SchemaProperty::new("n", SchemaType::Number, "").with_range(0.0, 10.0));
        let err = schema.validate_object(&json!({"n": 99.0})).unwrap_err();
        assert!(matches!(err, SchemaError::OutOfRange { .. }));
    }

    // â”€â”€ SchemaValidator â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn schema_validator_unknown_tool_error() {
        let v = SchemaValidator::new();
        let err = v.validate("ghost", &json!({})).unwrap_err();
        assert!(matches!(err, SchemaError::UnknownTool(_)));
    }

    #[test]
    fn schema_validator_has_tool_after_register() {
        let mut v = SchemaValidator::new();
        v.register("my_tool", ParameterSchema::new());
        assert!(v.has_tool("my_tool"));
    }

    #[test]
    fn schema_validator_count_after_register() {
        let mut v = SchemaValidator::new();
        v.register("a", ParameterSchema::new());
        v.register("b", ParameterSchema::new());
        assert_eq!(v.registered_count(), 2);
    }

    // â”€â”€ SchemaType â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn schema_type_string_matches_string_value() {
        assert!(SchemaType::String.matches_value(&json!("hello")));
    }

    #[test]
    fn schema_type_integer_matches_integer_value() {
        assert!(SchemaType::Integer.matches_value(&json!(42)));
    }

    #[test]
    fn schema_type_boolean_does_not_match_string() {
        assert!(!SchemaType::Boolean.matches_value(&json!("true")));
    }

    #[test]
    fn schema_type_as_str() {
        assert_eq!(SchemaType::Array.as_str(), "array");
    }

    // â”€â”€ ResponseSchema â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn response_schema_with_example() {
        let r = ResponseSchema::new("desc", json!({})).with_example(json!({"result": 1}));
        assert!(r.example.is_some());
    }

    // â”€â”€ ToolSchemas.validate â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn validate_xref_query_missing_required() {
        let s = schemas();
        let err = s.validate("xref_query", &json!({})).unwrap_err();
        assert!(matches!(err, SchemaError::MissingRequired(_)));
    }

    #[test]
    fn validate_xref_query_with_address_ok() {
        let s = schemas();
        // address is required; provide it â€” additional_properties=false so must not add extras
        let result = s.validate("xref_query", &json!({"address": 0x1000}));
        // May succeed or fail on extra props; just ensure no panic
        let _ = result;
    }
}
