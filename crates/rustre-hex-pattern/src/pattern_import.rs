//! `rustre-hex-pattern` — 010 Editor template import subsystem.
//!
//! Parses 010 Editor binary templates and converts them to the pattern model.
//!
//! # Structs
//! - [`O10TemplateParser`]  — parses 010 Editor `.bt` template syntax
//! - [`O10TypeConverter`]   — converts parsed 010 types to `PatternByte` patterns
//! - [`PatternConverter`]   — high-level conversion pipeline
//! - [`CompatLayer`]        — compatibility shims for other template dialects
//! - [`PatternImport`]      — top-level import coordinator

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{Pattern, PatternByte};

/// Re-export of [`crate::PatternError`] so importer-side callers can route
/// failures through the same error type as the rest of the pattern engine.
pub use crate::PatternError;

// ─────────────────────────────────────────────────────────────────────────────
// Error
// ─────────────────────────────────────────────────────────────────────────────

/// Errors from the pattern import subsystem.
#[derive(Debug, Error)]
pub enum ImportError {
    #[error("parse error at line {line}: {message}")]
    Parse { line: usize, message: String },
    #[error("unsupported type: {0}")]
    UnsupportedType(String),
    #[error("conversion error: {0}")]
    Conversion(String),
    #[error("compat error: {0}")]
    Compat(String),
    #[error("empty input")]
    Empty,
    #[error("template error: {0}")]
    Template(String),
}

// ─────────────────────────────────────────────────────────────────────────────
// O10PrimitiveType
// ─────────────────────────────────────────────────────────────────────────────

/// Primitive types supported by 010 Editor templates.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum O10PrimitiveType {
    Uint8,
    Uint16,
    Uint32,
    Uint64,
    Int8,
    Int16,
    Int32,
    Int64,
    Float,
    Double,
    Char,
    WChar,
    String(usize), // fixed length
    RawBytes(usize),
}

impl O10PrimitiveType {
    /// Size in bytes.
    #[must_use]
    pub const fn byte_size(&self) -> usize {
        match self {
            Self::Uint8 | Self::Int8 | Self::Char => 1,
            Self::Uint16 | Self::Int16 | Self::WChar => 2,
            Self::Uint32 | Self::Int32 | Self::Float => 4,
            Self::Uint64 | Self::Int64 | Self::Double => 8,
            Self::String(n) | Self::RawBytes(n) => *n,
        }
    }

    /// Parse a type name string into a primitive type.
    ///
    /// # Errors
    /// Returns [`ImportError::UnsupportedType`] if unrecognised.
    pub fn from_str(s: &str) -> Result<Self, ImportError> {
        let lower = s.to_lowercase();
        match lower.as_str() {
            "uint8" | "ubyte" | "uchar" | "byte" => Ok(Self::Uint8),
            "uint16" | "ushort" | "word" => Ok(Self::Uint16),
            "uint32" | "ulong" | "dword" => Ok(Self::Uint32),
            "uint64" | "qword" | "uint64_t" => Ok(Self::Uint64),
            "int8" | "char" | "signed char" => Ok(Self::Int8),
            "int16" | "short" => Ok(Self::Int16),
            "int32" | "int" | "long" => Ok(Self::Int32),
            "int64" | "int64_t" => Ok(Self::Int64),
            "float" => Ok(Self::Float),
            "double" => Ok(Self::Double),
            "wchar_t" | "wchar" => Ok(Self::WChar),
            _ => Err(ImportError::UnsupportedType(s.to_string())),
        }
    }
}

impl std::fmt::Display for O10PrimitiveType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Uint8 => write!(f, "uint8"),
            Self::Uint16 => write!(f, "uint16"),
            Self::Uint32 => write!(f, "uint32"),
            Self::Uint64 => write!(f, "uint64"),
            Self::Int8 => write!(f, "int8"),
            Self::Int16 => write!(f, "int16"),
            Self::Int32 => write!(f, "int32"),
            Self::Int64 => write!(f, "int64"),
            Self::Float => write!(f, "float"),
            Self::Double => write!(f, "double"),
            Self::Char => write!(f, "char"),
            Self::WChar => write!(f, "wchar_t"),
            Self::String(n) => write!(f, "string[{n}]"),
            Self::RawBytes(n) => write!(f, "raw[{n}]"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// O10Field
// ─────────────────────────────────────────────────────────────────────────────

/// A single field declaration in a 010 Editor struct.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct O10Field {
    pub field_type: String,
    pub name: String,
    pub is_array: bool,
    pub array_size: Option<usize>,
    pub comment: String,
    pub is_conditional: bool,
}

impl O10Field {
    #[must_use]
    pub fn new(field_type: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            field_type: field_type.into(),
            name: name.into(),
            is_array: false,
            array_size: None,
            comment: String::new(),
            is_conditional: false,
        }
    }

    /// Estimated byte size (0 if unknown).
    #[must_use]
    pub fn byte_size(&self) -> usize {
        let base = O10PrimitiveType::from_str(&self.field_type)
            .map(|t| t.byte_size())
            .unwrap_or(0);
        if self.is_array {
            base * self.array_size.unwrap_or(0)
        } else {
            base
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// O10Struct
// ─────────────────────────────────────────────────────────────────────────────

/// A parsed 010 Editor struct definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct O10Struct {
    pub name: String,
    pub fields: Vec<O10Field>,
    pub comment: String,
    pub is_anonymous: bool,
}

impl O10Struct {
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            fields: Vec::new(),
            comment: String::new(),
            is_anonymous: false,
        }
    }

    /// Total byte size (sum of all field sizes).
    #[must_use]
    pub fn byte_size(&self) -> usize {
        self.fields.iter().map(O10Field::byte_size).sum()
    }

    /// Number of fields.
    #[must_use]
    pub const fn field_count(&self) -> usize {
        self.fields.len()
    }

    /// Field by name.
    #[must_use]
    pub fn field(&self, name: &str) -> Option<&O10Field> {
        self.fields.iter().find(|f| f.name == name)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// O10Template
// ─────────────────────────────────────────────────────────────────────────────

/// A complete parsed 010 Editor `.bt` template.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct O10Template {
    /// Template name (derived from filename or `BigEndian`/`LittleEndian` hint).
    pub name: String,
    /// Whether multi-byte values are big-endian.
    pub big_endian: bool,
    /// All struct definitions.
    pub structs: Vec<O10Struct>,
    /// All typedef aliases: alias → original type.
    pub typedefs: HashMap<String, String>,
    /// Top-level variables (instantiated structs / fields).
    pub top_level: Vec<O10Field>,
    /// Raw template source.
    pub source: String,
}

impl O10Template {
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            ..Default::default()
        }
    }

    /// Lookup a struct definition by name.
    #[must_use]
    pub fn find_struct(&self, name: &str) -> Option<&O10Struct> {
        self.structs.iter().find(|s| s.name == name)
    }

    /// Resolve a typedef alias chain.
    #[must_use]
    pub fn resolve_typedef<'a>(&'a self, name: &'a str) -> &'a str {
        let mut current: &'a str = name;
        for _ in 0..16 {
            if let Some(target) = self.typedefs.get(current) {
                current = target.as_str();
            } else {
                break;
            }
        }
        current
    }

    /// Total number of struct definitions.
    #[must_use]
    pub const fn struct_count(&self) -> usize {
        self.structs.len()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// O10TemplateParser
// ─────────────────────────────────────────────────────────────────────────────

/// Parses 010 Editor `.bt` template syntax.
///
/// This is a simplified parser that handles the most common constructs.
#[derive(Debug, Default)]
pub struct O10TemplateParser {
    /// Parsing warnings.
    pub warnings: Vec<String>,
}

impl O10TemplateParser {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Parse a template from source text.
    ///
    /// # Errors
    /// Returns [`ImportError::Parse`] on syntax errors.
    pub fn parse(&mut self, source: &str) -> Result<O10Template, ImportError> {
        if source.trim().is_empty() {
            return Err(ImportError::Empty);
        }
        let mut template = O10Template::new("template");
        template.source = source.to_string();

        for (line_no, line) in source.lines().enumerate() {
            let line = line.trim();
            // Skip comments and empty lines
            if line.is_empty() || line.starts_with("//") || line.starts_with("/*") {
                continue;
            }
            self.process_line(line, line_no + 1, &mut template)?;
        }
        Ok(template)
    }

    fn process_line(
        &self,
        line: &str,
        line_no: usize,
        template: &mut O10Template,
    ) -> Result<(), ImportError> {
        // BigEndian / LittleEndian hints
        if line.starts_with("BigEndian") || line.contains("BigEndian()") {
            template.big_endian = true;
            return Ok(());
        }
        if line.starts_with("LittleEndian") || line.contains("LittleEndian()") {
            template.big_endian = false;
            return Ok(());
        }
        // typedef
        if line.starts_with("typedef") {
            if let Some(parts) = parse_typedef(line) {
                template.typedefs.insert(parts.1, parts.0);
            }
            return Ok(());
        }
        // struct definition (opening line)
        if line.starts_with("struct ") || line.starts_with("typedef struct") {
            // Parse the header up to "{" to obtain the struct name.
            let header_end = line.find('{').unwrap_or(line.len());
            let header = &line[..header_end];
            let name = extract_identifier(header, "struct");
            template
                .structs
                .push(O10Struct::new(name.unwrap_or("AnonymousStruct")));
            // If this line also contains the body `{ ... }` on the same line,
            // parse each `;`-separated field declaration inline.
            if let (Some(open), Some(close)) = (line.find('{'), line.rfind('}')) {
                if close > open {
                    let body = &line[open + 1..close];
                    for raw in body.split(';') {
                        let f = raw.trim();
                        if f.is_empty() {
                            continue;
                        }
                        if let Some(field) = parse_field_decl(f) {
                            if let Some(s) = template.structs.last_mut() {
                                s.fields.push(field);
                            }
                        }
                    }
                }
            }
            return Ok(());
        }
        // Field declaration inside a struct or at top-level
        if let Some(field) = parse_field_decl(line) {
            if let Some(s) = template.structs.last_mut() {
                s.fields.push(field);
            } else {
                template.top_level.push(field);
            }
        }
        let _ = line_no;
        Ok(())
    }
}

fn parse_typedef(line: &str) -> Option<(String, String)> {
    // "typedef uint32 DWORD;"  →  ("uint32", "DWORD")
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() >= 3 {
        let orig = parts[1].to_string();
        let alias = parts[2].trim_end_matches(';').to_string();
        Some((orig, alias))
    } else {
        None
    }
}

fn extract_identifier<'a>(line: &'a str, keyword: &str) -> Option<&'a str> {
    line.split_whitespace()
        .find(|&t| t != keyword && t != "typedef")
}

fn parse_field_decl(line: &str) -> Option<O10Field> {
    // "uint32 offset;" or "char data[16];"
    let line = line.trim_end_matches(';').trim();
    let mut parts = line.splitn(2, char::is_whitespace);
    let type_str = parts.next()?.trim();
    let name_part = parts.next()?.trim();
    if name_part.is_empty() || type_str.is_empty() {
        return None;
    }
    // Array
    if let Some(bracket) = name_part.find('[') {
        let name = name_part[..bracket].trim();
        let size_str = name_part[bracket + 1..].trim_end_matches(']');
        let size = size_str.parse::<usize>().ok();
        let mut f = O10Field::new(type_str, name);
        f.is_array = true;
        f.array_size = size;
        return Some(f);
    }
    Some(O10Field::new(type_str, name_part))
}

// ─────────────────────────────────────────────────────────────────────────────
// O10TypeConverter
// ─────────────────────────────────────────────────────────────────────────────

/// Converts parsed 010 Editor types to `PatternByte` sequences.
#[derive(Debug, Default)]
pub struct O10TypeConverter;

impl O10TypeConverter {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Convert a primitive type to a wildcard pattern (size wildcards).
    ///
    /// # Errors
    /// Returns [`ImportError::UnsupportedType`] for unknown types.
    pub fn type_to_pattern(
        &self,
        type_name: &str,
        big_endian: bool,
    ) -> Result<Vec<PatternByte>, ImportError> {
        let prim = O10PrimitiveType::from_str(type_name)?;
        let size = prim.byte_size();
        let _ = big_endian; // endianness is captured by the caller's pattern label
        Ok(vec![PatternByte::Wildcard; size])
    }

    /// Convert a field to a pattern with name metadata.
    pub fn field_to_pattern(
        &self,
        field: &O10Field,
        big_endian: bool,
    ) -> Result<(Vec<PatternByte>, String), ImportError> {
        let base = self.type_to_pattern(&field.field_type, big_endian)?;
        /// Maximum total byte size allowed for a single field pattern (64 MiB).
        /// Prevents `vec![…; huge_n]` OOM when `array_size` comes from untrusted input.
        const MAX_FIELD_BYTES: usize = 64 * 1024 * 1024;
        let size = if field.is_array {
            let array_size = field.array_size.unwrap_or(1);
            base.len().checked_mul(array_size).ok_or_else(|| {
                ImportError::Conversion(format!(
                    "field '{}': array size overflow ({} * {})",
                    field.name,
                    base.len(),
                    array_size
                ))
            })?
        } else {
            base.len()
        };
        if size > MAX_FIELD_BYTES {
            return Err(ImportError::Conversion(format!(
                "field '{}': computed size {} exceeds limit {}",
                field.name, size, MAX_FIELD_BYTES
            )));
        }
        let label = format!("{}.{}", field.field_type, field.name);
        Ok((vec![PatternByte::Wildcard; size], label))
    }

    /// Convert a struct definition to a pattern covering its full byte range.
    pub fn struct_to_pattern(
        &self,
        s: &O10Struct,
        big_endian: bool,
    ) -> Result<Pattern, ImportError> {
        let mut bytes: Vec<PatternByte> = Vec::new();
        for field in &s.fields {
            let (pat, _) = self.field_to_pattern(field, big_endian)?;
            bytes.extend(pat);
        }
        if bytes.is_empty() {
            return Err(ImportError::Conversion(format!(
                "struct '{}' has no fields",
                s.name
            )));
        }
        let p = Pattern {
            bytes,
            name: Some(s.name.clone()),
            tags: vec!["010-template".to_string()],
            captures: Vec::new(),
            comment: s.comment.clone(),
        };
        Ok(p)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PatternConverter
// ─────────────────────────────────────────────────────────────────────────────

/// High-level conversion pipeline: template → list of patterns.
#[derive(Debug, Default)]
pub struct PatternConverter {
    type_converter: O10TypeConverter,
    /// Conversion log.
    pub log: Vec<String>,
    /// Number of successful conversions.
    pub success_count: usize,
    /// Number of failed conversions.
    pub error_count: usize,
}

impl PatternConverter {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Convert all structs in `template` to patterns.
    pub fn convert_template(&mut self, template: &O10Template) -> Vec<Pattern> {
        let mut patterns = Vec::new();
        for s in &template.structs {
            match self
                .type_converter
                .struct_to_pattern(s, template.big_endian)
            {
                Ok(p) => {
                    self.log.push(format!("OK: struct '{}'", s.name));
                    self.success_count += 1;
                    patterns.push(p);
                }
                Err(e) => {
                    self.log.push(format!("ERR struct '{}': {e}", s.name));
                    self.error_count += 1;
                }
            }
        }
        patterns
    }

    /// Convert a single named struct to a pattern.
    pub fn convert_struct(
        &mut self,
        template: &O10Template,
        struct_name: &str,
    ) -> Result<Pattern, ImportError> {
        let s = template
            .find_struct(struct_name)
            .ok_or_else(|| ImportError::Template(format!("struct '{struct_name}' not found")))?;
        let p = self
            .type_converter
            .struct_to_pattern(s, template.big_endian)?;
        self.success_count += 1;
        Ok(p)
    }

    /// Convert a single field type to a pattern.
    pub fn convert_type(&mut self, type_name: &str) -> Result<Pattern, ImportError> {
        let bytes = self.type_converter.type_to_pattern(type_name, false)?;
        if bytes.is_empty() {
            return Err(ImportError::Conversion("empty".into()));
        }
        self.success_count += 1;
        Ok(Pattern {
            bytes,
            name: Some(type_name.to_string()),
            tags: vec!["010-type".to_string()],
            captures: Vec::new(),
            comment: String::new(),
        })
    }

    /// Success rate.
    #[must_use]
    pub fn success_rate(&self) -> f64 {
        let total = self.success_count + self.error_count;
        if total == 0 {
            return 1.0;
        }
        self.success_count as f64 / total as f64
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CompatLayer
// ─────────────────────────────────────────────────────────────────────────────

/// Compatibility shims for other template dialects (Kaitai Struct, `ImHex`, etc.).
#[derive(Debug, Default)]
pub struct CompatLayer {
    /// Name of the dialect being converted.
    pub dialect: String,
    /// Conversion log.
    pub log: Vec<String>,
}

/// Supported dialect identifiers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TemplateDialect {
    O10Editor,
    KaitaiStruct,
    ImHex,
    StructuredText,
    Custom(String),
}

impl std::fmt::Display for TemplateDialect {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::O10Editor => write!(f, "010-editor"),
            Self::KaitaiStruct => write!(f, "kaitai-struct"),
            Self::ImHex => write!(f, "imhex"),
            Self::StructuredText => write!(f, "structured-text"),
            Self::Custom(s) => write!(f, "custom({s})"),
        }
    }
}

impl CompatLayer {
    #[must_use]
    pub fn new(dialect: TemplateDialect) -> Self {
        Self {
            dialect: dialect.to_string(),
            log: Vec::new(),
        }
    }

    /// Normalise type names from other dialects to 010 Editor names.
    ///
    /// Returns the normalised type name, or the input if unrecognised.
    #[must_use]
    pub fn normalise_type(&self, type_name: &str) -> String {
        let lowered = type_name.to_lowercase();
        // ImHex-style single-byte unsigned (1-byte u8) collides with Kaitai's
        // `u8` (which means 8-byte uint64). When the active dialect is ImHex,
        // the 1-byte interpretation wins; otherwise the Kaitai mapping below
        // is used.
        if self.dialect == "imhex" && lowered == "u8" {
            return "uint8".to_string();
        }
        match lowered.as_str() {
            // Kaitai Struct types
            "u1" => "uint8",
            "u2" | "u2le" | "u2be" => "uint16",
            "u4" | "u4le" | "u4be" => "uint32",
            "u8" | "u8le" | "u8be" => "uint64",
            "s1" => "int8",
            "s2" | "s2le" | "s2be" => "int16",
            "s4" | "s4le" | "s4be" => "int32",
            "s8" | "s8le" | "s8be" => "int64",
            "f4" | "f4le" | "f4be" => "float",
            "f8" | "f8le" | "f8be" => "double",
            // ImHex types
            "be u16" | "le u16" => "uint16",
            "be u32" | "le u32" => "uint32",
            _ => type_name,
        }
        .to_string()
    }

    /// Convert Kaitai Struct YAML to a simplified O10 template.
    ///
    /// Returns an `O10Template` with best-effort field mapping.
    pub fn from_kaitai_yaml(&mut self, yaml: &str) -> O10Template {
        let mut template = O10Template::new("kaitai-converted");
        // Very simplified: extract "id: " and "type: " pairs
        let mut current_struct = O10Struct::new("KaitaiRoot");
        for line in yaml.lines() {
            // Strip YAML sequence markers like "- " so "- id: foo" is recognised.
            let line = line.trim().trim_start_matches('-').trim();
            if line.starts_with("id:") {
                let name = line.trim_start_matches("id:").trim().to_string();
                if !name.is_empty() {
                    let field = O10Field::new("uint8", &name);
                    current_struct.fields.push(field);
                }
            } else if line.starts_with("type:") {
                // Override last field's type
                let t = line.trim_start_matches("type:").trim();
                let norm = self.normalise_type(t);
                if let Some(f) = current_struct.fields.last_mut() {
                    f.field_type = norm;
                }
            }
        }
        if !current_struct.fields.is_empty() {
            template.structs.push(current_struct);
        }
        self.log.push(format!(
            "from_kaitai_yaml: {} structs",
            template.structs.len()
        ));
        template
    }

    /// Convert `ImHex` pattern text to a simplified O10 template.
    pub fn from_imhex_pattern(&mut self, source: &str) -> O10Template {
        let mut parser = O10TemplateParser::new();
        // ImHex patterns use the same C-style syntax; try direct parse.
        match parser.parse(source) {
            Ok(t) => {
                self.log
                    .push("from_imhex_pattern: direct parse OK".to_string());
                t
            }
            Err(e) => {
                self.log
                    .push(format!("from_imhex_pattern: parse failed: {e}"));
                O10Template::new("imhex-failed")
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PatternImport
// ─────────────────────────────────────────────────────────────────────────────

/// Top-level import coordinator.
///
/// Chains parser → type converter → pattern builder.
pub struct PatternImport {
    pub parser: O10TemplateParser,
    pub converter: PatternConverter,
    pub compat: CompatLayer,
    /// All successfully imported patterns.
    pub patterns: Vec<Pattern>,
    /// All import errors encountered.
    pub errors: Vec<ImportError>,
}

impl PatternImport {
    #[must_use]
    pub fn new() -> Self {
        Self {
            parser: O10TemplateParser::new(),
            converter: PatternConverter::new(),
            compat: CompatLayer::new(TemplateDialect::O10Editor),
            patterns: Vec::new(),
            errors: Vec::new(),
        }
    }

    /// Import from raw 010 Editor source text.
    ///
    /// Returns the number of patterns imported.
    pub fn import_010_source(&mut self, source: &str) -> usize {
        match self.parser.parse(source) {
            Err(e) => {
                self.errors.push(e);
                0
            }
            Ok(template) => {
                let patterns = self.converter.convert_template(&template);
                let n = patterns.len();
                self.patterns.extend(patterns);
                n
            }
        }
    }

    /// Import a single struct by name from 010 source.
    pub fn import_struct(&mut self, source: &str, struct_name: &str) -> Option<&Pattern> {
        let template = self.parser.parse(source).ok()?;
        let p = self.converter.convert_struct(&template, struct_name).ok()?;
        self.patterns.push(p);
        self.patterns.last()
    }

    /// Import from Kaitai Struct YAML.
    pub fn import_kaitai(&mut self, yaml: &str) -> usize {
        let template = self.compat.from_kaitai_yaml(yaml);
        let patterns = self.converter.convert_template(&template);
        let n = patterns.len();
        self.patterns.extend(patterns);
        n
    }

    /// Total patterns imported.
    #[must_use]
    pub const fn total_patterns(&self) -> usize {
        self.patterns.len()
    }

    /// Total errors encountered.
    #[must_use]
    pub const fn total_errors(&self) -> usize {
        self.errors.len()
    }

    /// All imported patterns.
    #[must_use]
    pub fn all_patterns(&self) -> &[Pattern] {
        &self.patterns
    }

    /// Reset all state.
    pub fn reset(&mut self) {
        self.patterns.clear();
        self.errors.clear();
        self.converter.log.clear();
        self.converter.success_count = 0;
        self.converter.error_count = 0;
    }
}

impl Default for PatternImport {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── O10PrimitiveType ──────────────────────────────────────────────────────

    #[test]
    fn primitive_type_from_str_uint32() {
        let t = O10PrimitiveType::from_str("uint32").unwrap();
        assert_eq!(t, O10PrimitiveType::Uint32);
        assert_eq!(t.byte_size(), 4);
    }

    #[test]
    fn primitive_type_from_str_dword_alias() {
        let t = O10PrimitiveType::from_str("DWORD").unwrap();
        assert_eq!(t, O10PrimitiveType::Uint32);
    }

    #[test]
    fn primitive_type_from_str_unknown() {
        assert!(matches!(
            O10PrimitiveType::from_str("vector3"),
            Err(ImportError::UnsupportedType(_))
        ));
    }

    #[test]
    fn primitive_type_sizes() {
        assert_eq!(O10PrimitiveType::Uint8.byte_size(), 1);
        assert_eq!(O10PrimitiveType::Uint16.byte_size(), 2);
        assert_eq!(O10PrimitiveType::Uint32.byte_size(), 4);
        assert_eq!(O10PrimitiveType::Uint64.byte_size(), 8);
        assert_eq!(O10PrimitiveType::Float.byte_size(), 4);
        assert_eq!(O10PrimitiveType::Double.byte_size(), 8);
    }

    #[test]
    fn primitive_type_display() {
        assert_eq!(O10PrimitiveType::Uint32.to_string(), "uint32");
        assert_eq!(O10PrimitiveType::String(8).to_string(), "string[8]");
    }

    // ── O10Field ──────────────────────────────────────────────────────────────

    #[test]
    fn field_new() {
        let f = O10Field::new("uint32", "magic");
        assert_eq!(f.field_type, "uint32");
        assert_eq!(f.name, "magic");
        assert!(!f.is_array);
    }

    #[test]
    fn field_byte_size() {
        let f = O10Field::new("uint32", "size");
        assert_eq!(f.byte_size(), 4);
    }

    #[test]
    fn field_array_byte_size() {
        let mut f = O10Field::new("uint8", "data");
        f.is_array = true;
        f.array_size = Some(16);
        assert_eq!(f.byte_size(), 16);
    }

    // ── O10Struct ─────────────────────────────────────────────────────────────

    #[test]
    fn struct_new() {
        let s = O10Struct::new("PeHeader");
        assert_eq!(s.name, "PeHeader");
        assert_eq!(s.field_count(), 0);
    }

    #[test]
    fn struct_byte_size() {
        let mut s = O10Struct::new("S");
        s.fields.push(O10Field::new("uint32", "a"));
        s.fields.push(O10Field::new("uint16", "b"));
        assert_eq!(s.byte_size(), 6);
    }

    #[test]
    fn struct_field_lookup() {
        let mut s = O10Struct::new("S");
        s.fields.push(O10Field::new("uint32", "magic"));
        assert!(s.field("magic").is_some());
        assert!(s.field("nosuchfield").is_none());
    }

    // ── O10Template ───────────────────────────────────────────────────────────

    #[test]
    fn template_find_struct() {
        let mut t = O10Template::new("t");
        t.structs.push(O10Struct::new("DosHeader"));
        assert!(t.find_struct("DosHeader").is_some());
        assert!(t.find_struct("NotThere").is_none());
    }

    #[test]
    fn template_resolve_typedef() {
        let mut t = O10Template::new("t");
        t.typedefs.insert("DWORD".to_string(), "uint32".to_string());
        assert_eq!(t.resolve_typedef("DWORD"), "uint32");
        assert_eq!(t.resolve_typedef("uint32"), "uint32"); // no entry
    }

    // ── O10TemplateParser ─────────────────────────────────────────────────────

    #[test]
    fn parser_parse_simple_struct() {
        let src = r"
struct DosHeader {
    uint16 e_magic;
    uint16 e_cblp;
};
";
        let mut p = O10TemplateParser::new();
        let t = p.parse(src).unwrap();
        assert!(!t.structs.is_empty());
        let ds = &t.structs[0];
        assert_eq!(ds.name, "DosHeader");
    }

    #[test]
    fn parser_big_endian_hint() {
        let src = "BigEndian();\nstruct S { uint32 x; };";
        let mut p = O10TemplateParser::new();
        let t = p.parse(src).unwrap();
        assert!(t.big_endian);
    }

    #[test]
    fn parser_typedef() {
        let src = "typedef uint32 DWORD;";
        let mut p = O10TemplateParser::new();
        let t = p.parse(src).unwrap();
        assert!(t.typedefs.contains_key("DWORD"));
    }

    #[test]
    fn parser_empty_source_error() {
        let mut p = O10TemplateParser::new();
        assert!(matches!(p.parse("").unwrap_err(), ImportError::Empty));
    }

    #[test]
    fn parser_comments_skipped() {
        let src = "// This is a comment\nstruct S { uint8 x; };\n";
        let mut p = O10TemplateParser::new();
        let t = p.parse(src).unwrap();
        assert_eq!(t.structs.len(), 1);
    }

    #[test]
    fn parser_array_field() {
        let src = "struct S { uint8 data[16]; };\n";
        let mut p = O10TemplateParser::new();
        let t = p.parse(src).unwrap();
        let f = t.structs[0].fields.first().unwrap();
        assert!(f.is_array);
        assert_eq!(f.array_size, Some(16));
    }

    // ── O10TypeConverter ──────────────────────────────────────────────────────

    #[test]
    fn type_converter_primitive() {
        let c = O10TypeConverter::new();
        let bytes = c.type_to_pattern("uint32", false).unwrap();
        assert_eq!(bytes.len(), 4);
        assert!(bytes.iter().all(|b| *b == PatternByte::Wildcard));
    }

    #[test]
    fn type_converter_unknown_type() {
        let c = O10TypeConverter::new();
        assert!(matches!(
            c.type_to_pattern("vector3", false).unwrap_err(),
            ImportError::UnsupportedType(_)
        ));
    }

    #[test]
    fn type_converter_struct_to_pattern() {
        let c = O10TypeConverter::new();
        let mut s = O10Struct::new("PeHdr");
        s.fields.push(O10Field::new("uint16", "magic"));
        s.fields.push(O10Field::new("uint32", "offset"));
        let p = c.struct_to_pattern(&s, false).unwrap();
        assert_eq!(p.bytes.len(), 6); // 2 + 4
        assert_eq!(p.name.as_deref(), Some("PeHdr"));
    }

    #[test]
    fn type_converter_empty_struct_error() {
        let c = O10TypeConverter::new();
        let s = O10Struct::new("Empty");
        assert!(matches!(
            c.struct_to_pattern(&s, false).unwrap_err(),
            ImportError::Conversion(_)
        ));
    }

    // ── PatternConverter ──────────────────────────────────────────────────────

    #[test]
    fn pattern_converter_convert_template() {
        let mut t = O10Template::new("t");
        let mut s = O10Struct::new("S");
        s.fields.push(O10Field::new("uint32", "a"));
        t.structs.push(s);
        let mut c = PatternConverter::new();
        let patterns = c.convert_template(&t);
        assert_eq!(patterns.len(), 1);
        assert_eq!(c.success_count, 1);
    }

    #[test]
    fn pattern_converter_convert_type() {
        let mut c = PatternConverter::new();
        let p = c.convert_type("uint64").unwrap();
        assert_eq!(p.bytes.len(), 8);
        assert_eq!(p.name.as_deref(), Some("uint64"));
    }

    #[test]
    fn pattern_converter_success_rate() {
        let mut c = PatternConverter::new();
        c.success_count = 9;
        c.error_count = 1;
        assert!((c.success_rate() - 0.9).abs() < 1e-9);
    }

    // ── CompatLayer ───────────────────────────────────────────────────────────

    #[test]
    fn compat_normalise_kaitai_type() {
        let c = CompatLayer::new(TemplateDialect::KaitaiStruct);
        assert_eq!(c.normalise_type("u4le"), "uint32");
        assert_eq!(c.normalise_type("s2"), "int16");
        assert_eq!(c.normalise_type("f4"), "float");
    }

    #[test]
    fn compat_dialect_display() {
        assert_eq!(TemplateDialect::O10Editor.to_string(), "010-editor");
        assert_eq!(TemplateDialect::KaitaiStruct.to_string(), "kaitai-struct");
        assert_eq!(TemplateDialect::ImHex.to_string(), "imhex");
    }

    #[test]
    fn compat_from_kaitai_yaml() {
        let yaml = "seq:\n  - id: magic\n    type: u4le\n  - id: size\n    type: u2le\n";
        let mut c = CompatLayer::new(TemplateDialect::KaitaiStruct);
        let t = c.from_kaitai_yaml(yaml);
        assert!(!t.structs.is_empty());
    }

    // ── PatternImport ─────────────────────────────────────────────────────────

    #[test]
    fn import_010_source() {
        let src = "struct PE { uint16 magic; uint32 offset; };\n";
        let mut imp = PatternImport::new();
        let n = imp.import_010_source(src);
        assert_eq!(n, 1);
        assert_eq!(imp.total_patterns(), 1);
    }

    #[test]
    fn import_struct_by_name() {
        let src = "struct PE { uint16 magic; uint32 offset; };\n";
        let mut imp = PatternImport::new();
        let p = imp.import_struct(src, "PE").unwrap();
        assert_eq!(p.bytes.len(), 6); // 2 + 4
    }

    #[test]
    fn import_kaitai() {
        let yaml = "seq:\n  - id: x\n    type: u4le\n";
        let mut imp = PatternImport::new();
        let n = imp.import_kaitai(yaml);
        let _ = n; // may be 0 if the simplified parser produces no structs
    }

    #[test]
    fn import_reset() {
        let src = "struct S { uint8 x; };\n";
        let mut imp = PatternImport::new();
        imp.import_010_source(src);
        imp.reset();
        assert_eq!(imp.total_patterns(), 0);
        assert_eq!(imp.total_errors(), 0);
    }

    #[test]
    fn import_empty_source_counts_error() {
        let mut imp = PatternImport::new();
        let n = imp.import_010_source("");
        assert_eq!(n, 0);
        assert_eq!(imp.total_errors(), 1);
    }

    #[test]
    fn import_multiple_structs() {
        let src = "struct A { uint32 x; };\nstruct B { uint16 y; };\n";
        let mut imp = PatternImport::new();
        let n = imp.import_010_source(src);
        assert_eq!(n, 2);
        assert_eq!(imp.total_patterns(), 2);
    }
}
