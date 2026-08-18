//! `rustre-hex-template` — Binary templates (010 Editor–style).
//!
//! Apply structured templates to a `HexBuffer`, producing a `ParsedStruct`
//! tree of typed fields.  Comes with built-in templates for common formats:
//! PE/COFF, ELF32/64, ZIP, PNG, BMP, JPEG, GIF, PDF, MZ/DOS.

pub mod builtin_templates;
pub mod template_library;
pub mod template_auto_detect;
pub mod template_composition;
pub mod template_engine;
pub mod template_stdlib;
pub mod template_compiler;
pub mod struct_extractor;
pub mod template_type_system;
pub mod template_interpreter;
pub mod template_expression_eval;

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use rustre_hex::{DataType, Encoding, HexBuffer, HexError, TypedValue};

// ─────────────────────────────────────────────────────────────────────────────
// Errors
// ─────────────────────────────────────────────────────────────────────────────

/// Errors produced by the template engine.
#[derive(Debug, Error)]
pub enum TemplateError {
    #[error("field '{0}': {1}")]
    Field(String, String),
    #[error("hex error: {0}")]
    Hex(#[from] HexError),
    #[error("condition error: {0}")]
    Condition(String),
    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("template '{0}' not found")]
    NotFound(String),
    #[error("recursive template depth exceeded")]
    RecursionLimit,
    #[error("field '{0}' referenced in repeat/condition not found")]
    FieldRef(String),
}

// ─────────────────────────────────────────────────────────────────────────────
// Expr — conditional expressions
// ─────────────────────────────────────────────────────────────────────────────

/// A boolean condition expression over previously-parsed field values.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Expr {
    /// `field == value`
    Eq(String, u64),
    /// `field != value`
    Ne(String, u64),
    /// `field > value`
    Gt(String, u64),
    /// `field < value`
    Lt(String, u64),
    /// `a && b`
    And(Box<Expr>, Box<Expr>),
    /// `a || b`
    Or(Box<Expr>, Box<Expr>),
}

impl Expr {
    /// Evaluate the expression against a map of previously resolved field values.
    pub fn eval(&self, ctx: &HashMap<String, u64>) -> Result<bool, TemplateError> {
        match self {
            Self::Eq(name, val) => {
                let v = ctx
                    .get(name)
                    .copied()
                    .ok_or_else(|| TemplateError::Condition(format!("unknown field '{name}'")))?;
                Ok(v == *val)
            }
            Self::Ne(name, val) => {
                let v = ctx
                    .get(name)
                    .copied()
                    .ok_or_else(|| TemplateError::Condition(format!("unknown field '{name}'")))?;
                Ok(v != *val)
            }
            Self::Gt(name, val) => {
                let v = ctx
                    .get(name)
                    .copied()
                    .ok_or_else(|| TemplateError::Condition(format!("unknown field '{name}'")))?;
                Ok(v > *val)
            }
            Self::Lt(name, val) => {
                let v = ctx
                    .get(name)
                    .copied()
                    .ok_or_else(|| TemplateError::Condition(format!("unknown field '{name}'")))?;
                Ok(v < *val)
            }
            Self::And(a, b) => Ok(a.eval(ctx)? && b.eval(ctx)?),
            Self::Or(a, b) => Ok(a.eval(ctx)? || b.eval(ctx)?),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// RepeatSpec
// ─────────────────────────────────────────────────────────────────────────────

/// Repetition specification for a field.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RepeatSpec {
    /// Repeat a fixed number of times.
    Count(usize),
    /// Repeat while the named field is not equal to `not_value`.
    WhileField { field: String, not_value: u64 },
}

// ─────────────────────────────────────────────────────────────────────────────
// TemplateType
// ─────────────────────────────────────────────────────────────────────────────

/// Type of a template field.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TemplateType {
    /// Primitive scalar / bytes / cstr.
    Primitive(DataType),
    /// Nested struct.
    Struct(Vec<FieldDef>),
    /// Enum: read a primitive, then map to a variant name.
    Enum {
        ty: DataType,
        variants: Vec<(String, u64)>,
    },
    /// Fixed-count array.
    Array { ty: Box<TemplateType>, count: usize },
    /// Dynamic array whose count comes from a previously-parsed field.
    DynArray {
        ty: Box<TemplateType>,
        count_field: String,
    },
    /// String with encoding and optional fixed length (in code units).
    String {
        encoding: Encoding,
        /// Length in code units; `None` = null-terminated.
        len: Option<usize>,
    },
}

// ─────────────────────────────────────────────────────────────────────────────
// FieldDef
// ─────────────────────────────────────────────────────────────────────────────

/// Definition of a single field in a template.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldDef {
    pub name: String,
    pub ty: TemplateType,
    /// Explicit byte offset; if `None`, parsed sequentially.
    pub offset: Option<usize>,
    /// Field is only parsed when this expression is `true`.
    pub condition: Option<Expr>,
    /// Repeat this field according to the spec.
    pub repeat: Option<RepeatSpec>,
    pub comment: String,
}

impl FieldDef {
    /// Create a simple field with a name and a primitive type.
    #[must_use]
    pub fn new(name: impl Into<String>, ty: TemplateType) -> Self {
        Self {
            name: name.into(),
            ty,
            offset: None,
            condition: None,
            repeat: None,
            comment: String::new(),
        }
    }

    #[must_use]
    pub fn with_comment(mut self, comment: impl Into<String>) -> Self {
        self.comment = comment.into();
        self
    }

    #[must_use]
    pub const fn with_offset(mut self, offset: usize) -> Self {
        self.offset = Some(offset);
        self
    }

    #[must_use]
    pub fn with_condition(mut self, expr: Expr) -> Self {
        self.condition = Some(expr);
        self
    }

    #[must_use]
    pub fn with_repeat(mut self, spec: RepeatSpec) -> Self {
        self.repeat = Some(spec);
        self
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Template
// ─────────────────────────────────────────────────────────────────────────────

/// A named binary template consisting of a list of field definitions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Template {
    pub name: String,
    pub description: String,
    pub fields: Vec<FieldDef>,
}

impl Template {
    /// Create a new template.
    #[must_use]
    pub fn new(name: impl Into<String>, description: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
            fields: Vec::new(),
        }
    }

    /// Add a field to this template.
    pub fn add_field(&mut self, field: FieldDef) {
        self.fields.push(field);
    }

    /// Serialize to JSON.
    pub fn to_json(&self) -> Result<String, TemplateError> {
        Ok(serde_json::to_string_pretty(self)?)
    }

    /// Deserialize from JSON.
    pub fn from_json(json: &str) -> Result<Self, TemplateError> {
        Ok(serde_json::from_str(json)?)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ParsedField / ParsedStruct
// ─────────────────────────────────────────────────────────────────────────────

/// A single resolved field from applying a template.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsedField {
    pub name: String,
    pub offset: usize,
    pub size: usize,
    pub value: TypedValue,
    /// For struct/array/enum fields, the nested structure.
    pub children: Option<ParsedStruct>,
}

/// A resolved struct produced by applying a template.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ParsedStruct {
    pub name: String,
    pub fields: Vec<ParsedField>,
}

impl ParsedStruct {
    /// Look up a field value as a `u64` (for use in conditions and counts).
    #[must_use]
    pub fn field_as_u64(&self, name: &str) -> Option<u64> {
        self.fields
            .iter()
            .find(|f| f.name == name)
            .and_then(|f| typed_value_to_u64(&f.value))
    }

    /// Build a context map of `field_name → u64` for condition evaluation.
    #[must_use]
    pub fn context(&self) -> HashMap<String, u64> {
        self.fields
            .iter()
            .filter_map(|f| typed_value_to_u64(&f.value).map(|v| (f.name.clone(), v)))
            .collect()
    }
}

const fn typed_value_to_u64(v: &TypedValue) -> Option<u64> {
    match v {
        TypedValue::U8(x) => Some(*x as u64),
        TypedValue::U16(x) => Some(*x as u64),
        TypedValue::U32(x) => Some(*x as u64),
        TypedValue::U64(x) => Some(*x),
        TypedValue::I8(x) => Some(*x as u64),
        TypedValue::I16(x) => Some(*x as u64),
        TypedValue::I32(x) => Some(*x as u64),
        TypedValue::I64(x) => Some(*x as u64),
        _ => None,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TemplateApplier
// ─────────────────────────────────────────────────────────────────────────────

const MAX_RECURSION: usize = 32;
const MAX_ARRAY_ELEMENTS: usize = 65536;

/// Applies a `Template` to a `HexBuffer`, producing a `ParsedStruct`.
pub struct TemplateApplier<'a> {
    buf: &'a HexBuffer,
}

impl<'a> TemplateApplier<'a> {
    /// Create a new applier for the given buffer.
    #[must_use]
    pub const fn new(buf: &'a HexBuffer) -> Self {
        Self { buf }
    }

    /// Apply `template` starting at `base_offset`.
    pub fn apply(
        &self,
        template: &Template,
        base_offset: usize,
    ) -> Result<ParsedStruct, TemplateError> {
        self.apply_fields(
            &template.name,
            &template.fields,
            base_offset,
            &HashMap::new(),
            0,
        )
    }

    fn apply_fields(
        &self,
        struct_name: &str,
        fields: &[FieldDef],
        base_offset: usize,
        parent_ctx: &HashMap<String, u64>,
        depth: usize,
    ) -> Result<ParsedStruct, TemplateError> {
        if depth > MAX_RECURSION {
            return Err(TemplateError::RecursionLimit);
        }
        let mut parsed = ParsedStruct {
            name: struct_name.to_string(),
            fields: Vec::new(),
        };
        let mut cursor = base_offset;
        let mut ctx: HashMap<String, u64> = parent_ctx.clone();

        for field in fields {
            // Conditional skip
            if let Some(cond) = &field.condition
                && !cond
                    .eval(&ctx)
                    .map_err(|e| TemplateError::Field(field.name.clone(), e.to_string()))?
                {
                    continue;
                }

            let field_offset = field.offset.unwrap_or(cursor);

            match &field.repeat {
                None => {
                    let pf = self.parse_field(field, field_offset, &ctx, depth + 1)?;
                    let end = field_offset + pf.size;
                    if end > cursor {
                        cursor = end;
                    }
                    if let Some(v) = typed_value_to_u64(&pf.value) {
                        ctx.insert(field.name.clone(), v);
                    }
                    parsed.fields.push(pf);
                }
                Some(RepeatSpec::Count(n)) => {
                    let count = *n;
                    let mut off = field_offset;
                    for i in 0..count {
                        let elem_name = format!("{}[{i}]", field.name);
                        let sub_field = FieldDef {
                            name: elem_name,
                            ty: field.ty.clone(),
                            offset: None,
                            condition: None,
                            repeat: None,
                            comment: field.comment.clone(),
                        };
                        let pf = self.parse_field(&sub_field, off, &ctx, depth + 1)?;
                        off += pf.size;
                        parsed.fields.push(pf);
                    }
                    cursor = off;
                }
                Some(RepeatSpec::WhileField {
                    field: fname,
                    not_value,
                }) => {
                    let mut off = field_offset;
                    let mut i = 0usize;
                    loop {
                        let check = ctx
                            .get(fname)
                            .copied()
                            .ok_or_else(|| TemplateError::FieldRef(fname.clone()))?;
                        if check == *not_value {
                            break;
                        }
                        let elem_name = format!("{}[{i}]", field.name);
                        let sub_field = FieldDef {
                            name: elem_name,
                            ty: field.ty.clone(),
                            offset: None,
                            condition: None,
                            repeat: None,
                            comment: field.comment.clone(),
                        };
                        let pf = self.parse_field(&sub_field, off, &ctx, depth + 1)?;
                        off += pf.size;
                        // Update ctx so the WhileField condition can change between iterations.
                        // If the parsed element itself carries a value for `fname`, refresh it.
                        if let Some(v) = typed_value_to_u64(&pf.value) {
                            ctx.insert(fname.clone(), v);
                        }
                        // Also check children for a field named `fname`.
                        if let Some(ref children) = pf.children {
                            for child in &children.fields {
                                if child.name == *fname {
                                    if let Some(v) = typed_value_to_u64(&child.value) {
                                        ctx.insert(fname.clone(), v);
                                    }
                                }
                            }
                        }
                        parsed.fields.push(pf);
                        i += 1;
                        // Avoid infinite loops on corrupt data
                        if i >= MAX_ARRAY_ELEMENTS {
                            break;
                        }
                    }
                    cursor = off;
                }
            }
        }
        Ok(parsed)
    }

    fn parse_field(
        &self,
        field: &FieldDef,
        offset: usize,
        ctx: &HashMap<String, u64>,
        depth: usize,
    ) -> Result<ParsedField, TemplateError> {
        match &field.ty {
            TemplateType::Primitive(dt) => {
                let value = self
                    .buf
                    .read_typed(offset, dt.clone())
                    .map_err(|e| TemplateError::Field(field.name.clone(), e.to_string()))?;
                let size = dt.fixed_size().unwrap_or_else(|| {
                    // CStr: find null
                    match &value {
                        TypedValue::Str(s) => s.len() + 1,
                        TypedValue::Bytes(b) => b.len(),
                        _ => 0,
                    }
                });
                Ok(ParsedField {
                    name: field.name.clone(),
                    offset,
                    size,
                    value,
                    children: None,
                })
            }
            TemplateType::Enum { ty, variants } => {
                let raw = self
                    .buf
                    .read_typed(offset, ty.clone())
                    .map_err(|e| TemplateError::Field(field.name.clone(), e.to_string()))?;
                let size = ty.fixed_size().unwrap_or(1);
                let disc = typed_value_to_u64(&raw).unwrap_or(0);
                let label = variants
                    .iter()
                    .find(|(_, v)| *v == disc)
                    .map(|(name, _)| name.clone())
                    .unwrap_or_else(|| format!("unknown({disc})"));
                Ok(ParsedField {
                    name: field.name.clone(),
                    offset,
                    size,
                    value: TypedValue::Str(label),
                    children: None,
                })
            }
            TemplateType::Struct(sub_fields) => {
                let sub = self.apply_fields(&field.name, sub_fields, offset, ctx, depth)?;
                let size = sub
                    .fields
                    .iter()
                    .map(|f| f.offset.saturating_add(f.size))
                    .max()
                    .unwrap_or(offset)
                    .saturating_sub(offset);
                Ok(ParsedField {
                    name: field.name.clone(),
                    offset,
                    size,
                    value: TypedValue::Bytes(vec![]),
                    children: Some(sub),
                })
            }
            TemplateType::Array { ty, count } => {
                let mut sub = ParsedStruct {
                    name: field.name.clone(),
                    fields: Vec::new(),
                };
                let mut off = offset;
                for i in 0..*count {
                    let sub_def = FieldDef::new(format!("[{i}]"), *ty.clone());
                    let pf = self.parse_field(&sub_def, off, ctx, depth)?;
                    off += pf.size;
                    sub.fields.push(pf);
                }
                let size = off.saturating_sub(offset);
                Ok(ParsedField {
                    name: field.name.clone(),
                    offset,
                    size,
                    value: TypedValue::Bytes(vec![]),
                    children: Some(sub),
                })
            }
            TemplateType::DynArray { ty, count_field } => {
                let raw_count = ctx
                    .get(count_field)
                    .copied()
                    .ok_or_else(|| TemplateError::FieldRef(count_field.clone()))?;
                if raw_count > MAX_ARRAY_ELEMENTS as u64 {
                    return Err(TemplateError::Field(
                        field.name.clone(),
                        format!(
                            "DynArray count {raw_count} exceeds maximum of {MAX_ARRAY_ELEMENTS}"
                        ),
                    ));
                }
                let count = raw_count as usize;
                let mut sub = ParsedStruct {
                    name: field.name.clone(),
                    fields: Vec::new(),
                };
                let mut off = offset;
                for i in 0..count {
                    let sub_def = FieldDef::new(format!("[{i}]"), *ty.clone());
                    let pf = self.parse_field(&sub_def, off, ctx, depth)?;
                    off += pf.size;
                    sub.fields.push(pf);
                }
                let size = off.saturating_sub(offset);
                Ok(ParsedField {
                    name: field.name.clone(),
                    offset,
                    size,
                    value: TypedValue::Bytes(vec![]),
                    children: Some(sub),
                })
            }
            TemplateType::String { encoding, len } => {
                let value = match len {
                    Some(n) => {
                        let dt = match encoding {
                            Encoding::Utf16Le | Encoding::Utf16Be => DataType::Utf16(*n),
                            _ => DataType::Bytes(*n),
                        };
                        self.buf
                            .read_typed(offset, dt)
                            .map_err(|e| TemplateError::Field(field.name.clone(), e.to_string()))?
                    }
                    None => self
                        .buf
                        .read_typed(offset, DataType::CStr)
                        .map_err(|e| TemplateError::Field(field.name.clone(), e.to_string()))?,
                };
                let size = match &value {
                    TypedValue::Str(s) => {
                        match len {
                            Some(n) => match encoding {
                                Encoding::Utf16Le | Encoding::Utf16Be => n * 2,
                                _ => *n,
                            },
                            None => s.len() + 1, // +1 for null terminator
                        }
                    }
                    TypedValue::Bytes(b) => b.len(),
                    _ => 0,
                };
                Ok(ParsedField {
                    name: field.name.clone(),
                    offset,
                    size,
                    value,
                    children: None,
                })
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Built-in templates
// ─────────────────────────────────────────────────────────────────────────────

/// Returns a library of built-in templates keyed by name.
#[must_use]
pub fn builtin_templates() -> HashMap<String, Template> {
    let mut map = HashMap::new();
    map.insert("MZ".to_string(), template_mz());
    map.insert("PE_COFF".to_string(), template_pe_coff());
    map.insert("ELF32".to_string(), template_elf32());
    map.insert("ELF64".to_string(), template_elf64());
    map.insert("ZIP".to_string(), template_zip());
    map.insert("PNG".to_string(), template_png());
    map.insert("BMP".to_string(), template_bmp());
    map.insert("JPEG".to_string(), template_jpeg());
    map.insert("GIF".to_string(), template_gif());
    map.insert("PDF".to_string(), template_pdf());
    map
}

const fn p(dt: DataType) -> TemplateType {
    TemplateType::Primitive(dt)
}

fn u8_field(name: &str) -> FieldDef {
    FieldDef::new(name, p(DataType::U8))
}

fn u16_field(name: &str) -> FieldDef {
    FieldDef::new(name, p(DataType::U16Le))
}

fn u32_field(name: &str) -> FieldDef {
    FieldDef::new(name, p(DataType::U32Le))
}

fn u64_field(name: &str) -> FieldDef {
    FieldDef::new(name, p(DataType::U64Le))
}

fn bytes_field(name: &str, n: usize) -> FieldDef {
    FieldDef::new(name, p(DataType::Bytes(n)))
}

// ── MZ/DOS header ─────────────────────────────────────────────────────────────

/// Public accessor for the built-in MZ/DOS template (used by wire wrappers as a default).
#[must_use]
pub fn template_mz_pub() -> Template {
    template_mz()
}

fn template_mz() -> Template {
    let mut t = Template::new("MZ", "MS-DOS MZ executable header");
    t.add_field(bytes_field("e_magic", 2).with_comment("MZ signature"));
    t.add_field(u16_field("e_cblp").with_comment("bytes on last page"));
    t.add_field(u16_field("e_cp").with_comment("pages in file"));
    t.add_field(u16_field("e_crlc").with_comment("relocations"));
    t.add_field(u16_field("e_cparhdr").with_comment("size of header in paragraphs"));
    t.add_field(u16_field("e_minalloc"));
    t.add_field(u16_field("e_maxalloc"));
    t.add_field(u16_field("e_ss"));
    t.add_field(u16_field("e_sp"));
    t.add_field(u16_field("e_csum"));
    t.add_field(u16_field("e_ip"));
    t.add_field(u16_field("e_cs"));
    t.add_field(u16_field("e_lfarlc"));
    t.add_field(u16_field("e_ovno"));
    t.add_field(bytes_field("e_res", 8));
    t.add_field(u16_field("e_oemid"));
    t.add_field(u16_field("e_oeminfo"));
    t.add_field(bytes_field("e_res2", 20));
    t.add_field(u32_field("e_lfanew").with_comment("file offset of PE header"));
    t
}

// ── PE/COFF ────────────────────────────────────────────────────────────────────

fn template_pe_coff() -> Template {
    let mut t = Template::new("PE_COFF", "PE/COFF file header");
    t.add_field(bytes_field("Signature", 4).with_comment("PE\\0\\0"));
    // COFF file header
    t.add_field(u16_field("Machine"));
    t.add_field(u16_field("NumberOfSections"));
    t.add_field(u32_field("TimeDateStamp"));
    t.add_field(u32_field("PointerToSymbolTable"));
    t.add_field(u32_field("NumberOfSymbols"));
    t.add_field(u16_field("SizeOfOptionalHeader"));
    t.add_field(u16_field("Characteristics"));
    t
}

// ── ELF32 ─────────────────────────────────────────────────────────────────────

fn template_elf32() -> Template {
    let mut t = Template::new("ELF32", "ELF 32-bit header");
    t.add_field(bytes_field("e_ident", 16).with_comment("ELF magic + class + data + version"));
    t.add_field(u16_field("e_type"));
    t.add_field(u16_field("e_machine"));
    t.add_field(u32_field("e_version"));
    t.add_field(u32_field("e_entry"));
    t.add_field(u32_field("e_phoff"));
    t.add_field(u32_field("e_shoff"));
    t.add_field(u32_field("e_flags"));
    t.add_field(u16_field("e_ehsize"));
    t.add_field(u16_field("e_phentsize"));
    t.add_field(u16_field("e_phnum"));
    t.add_field(u16_field("e_shentsize"));
    t.add_field(u16_field("e_shnum"));
    t.add_field(u16_field("e_shstrndx"));
    t
}

// ── ELF64 ─────────────────────────────────────────────────────────────────────

fn template_elf64() -> Template {
    let mut t = Template::new("ELF64", "ELF 64-bit header");
    t.add_field(bytes_field("e_ident", 16));
    t.add_field(u16_field("e_type"));
    t.add_field(u16_field("e_machine"));
    t.add_field(u32_field("e_version"));
    t.add_field(u64_field("e_entry"));
    t.add_field(u64_field("e_phoff"));
    t.add_field(u64_field("e_shoff"));
    t.add_field(u32_field("e_flags"));
    t.add_field(u16_field("e_ehsize"));
    t.add_field(u16_field("e_phentsize"));
    t.add_field(u16_field("e_phnum"));
    t.add_field(u16_field("e_shentsize"));
    t.add_field(u16_field("e_shnum"));
    t.add_field(u16_field("e_shstrndx"));
    t
}

// ── ZIP ───────────────────────────────────────────────────────────────────────

fn template_zip() -> Template {
    let mut t = Template::new("ZIP", "ZIP local file header");
    t.add_field(bytes_field("Signature", 4).with_comment("PK\\x03\\x04"));
    t.add_field(u16_field("VersionNeeded"));
    t.add_field(u16_field("GeneralPurposeBitFlag"));
    t.add_field(u16_field("CompressionMethod"));
    t.add_field(u16_field("LastModFileTime"));
    t.add_field(u16_field("LastModFileDate"));
    t.add_field(u32_field("Crc32"));
    t.add_field(u32_field("CompressedSize"));
    t.add_field(u32_field("UncompressedSize"));
    t.add_field(u16_field("FileNameLength"));
    t.add_field(u16_field("ExtraFieldLength"));
    t
}

// ── PNG ───────────────────────────────────────────────────────────────────────

fn template_png() -> Template {
    let mut t = Template::new("PNG", "PNG file header + IHDR chunk");
    t.add_field(bytes_field("Signature", 8).with_comment("\\x89PNG\\r\\n\\x1a\\n"));
    // IHDR chunk
    t.add_field(u32_field("IHDR_Length"));
    t.add_field(bytes_field("IHDR_Type", 4));
    t.add_field(FieldDef::new("Width", p(DataType::U32Be)));
    t.add_field(FieldDef::new("Height", p(DataType::U32Be)));
    t.add_field(u8_field("BitDepth"));
    t.add_field(u8_field("ColorType"));
    t.add_field(u8_field("CompressionMethod"));
    t.add_field(u8_field("FilterMethod"));
    t.add_field(u8_field("InterlaceMethod"));
    t.add_field(u32_field("IHDR_CRC"));
    t
}

// ── BMP ───────────────────────────────────────────────────────────────────────

fn template_bmp() -> Template {
    let mut t = Template::new("BMP", "BMP file header");
    t.add_field(bytes_field("bfType", 2).with_comment("BM"));
    t.add_field(u32_field("bfSize"));
    t.add_field(u16_field("bfReserved1"));
    t.add_field(u16_field("bfReserved2"));
    t.add_field(u32_field("bfOffBits"));
    // DIB header (BITMAPINFOHEADER)
    t.add_field(u32_field("biSize"));
    t.add_field(FieldDef::new("biWidth", p(DataType::I32Le)));
    t.add_field(FieldDef::new("biHeight", p(DataType::I32Le)));
    t.add_field(u16_field("biPlanes"));
    t.add_field(u16_field("biBitCount"));
    t.add_field(u32_field("biCompression"));
    t.add_field(u32_field("biSizeImage"));
    t.add_field(FieldDef::new("biXPelsPerMeter", p(DataType::I32Le)));
    t.add_field(FieldDef::new("biYPelsPerMeter", p(DataType::I32Le)));
    t.add_field(u32_field("biClrUsed"));
    t.add_field(u32_field("biClrImportant"));
    t
}

// ── JPEG ─────────────────────────────────────────────────────────────────────

fn template_jpeg() -> Template {
    let mut t = Template::new("JPEG", "JPEG SOI + APP0/JFIF marker");
    t.add_field(bytes_field("SOI", 2).with_comment("\\xFF\\xD8"));
    t.add_field(bytes_field("APP0Marker", 2).with_comment("\\xFF\\xE0"));
    t.add_field(FieldDef::new("APP0Length", p(DataType::U16Be)));
    t.add_field(bytes_field("Identifier", 5).with_comment("JFIF\\0"));
    t.add_field(u8_field("VersionMajor"));
    t.add_field(u8_field("VersionMinor"));
    t.add_field(u8_field("PixelAspectRatio"));
    t.add_field(FieldDef::new("Xdensity", p(DataType::U16Be)));
    t.add_field(FieldDef::new("Ydensity", p(DataType::U16Be)));
    t.add_field(u8_field("Xthumbnail"));
    t.add_field(u8_field("Ythumbnail"));
    t
}

// ── GIF ──────────────────────────────────────────────────────────────────────

fn template_gif() -> Template {
    let mut t = Template::new("GIF", "GIF89a/87a header + Logical Screen Descriptor");
    t.add_field(bytes_field("Signature", 3).with_comment("GIF"));
    t.add_field(bytes_field("Version", 3).with_comment("87a or 89a"));
    t.add_field(u16_field("LogicalScreenWidth"));
    t.add_field(u16_field("LogicalScreenHeight"));
    t.add_field(u8_field("PackedField"));
    t.add_field(u8_field("BackgroundColorIndex"));
    t.add_field(u8_field("PixelAspectRatio"));
    t
}

// ── PDF header ────────────────────────────────────────────────────────────────

fn template_pdf() -> Template {
    let mut t = Template::new("PDF", "PDF file header (magic bytes)");
    t.add_field(bytes_field("Magic", 4).with_comment("%PDF"));
    t.add_field(u8_field("Dash"));
    t.add_field(u8_field("MajorVersion"));
    t.add_field(u8_field("Dot"));
    t.add_field(u8_field("MinorVersion"));
    t
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn buf(data: &[u8]) -> HexBuffer {
        HexBuffer::new(data.to_vec())
    }

    // ── Expr ─────────────────────────────────────────────────────────────────

    #[test]
    fn test_expr_eq_true() {
        let mut ctx = HashMap::new();
        ctx.insert("x".to_string(), 42u64);
        assert!(Expr::Eq("x".to_string(), 42).eval(&ctx).unwrap());
    }

    #[test]
    fn test_expr_eq_false() {
        let mut ctx = HashMap::new();
        ctx.insert("x".to_string(), 1u64);
        assert!(!Expr::Eq("x".to_string(), 42).eval(&ctx).unwrap());
    }

    #[test]
    fn test_expr_and() {
        let mut ctx = HashMap::new();
        ctx.insert("a".to_string(), 1);
        ctx.insert("b".to_string(), 2);
        let expr = Expr::And(
            Box::new(Expr::Eq("a".to_string(), 1)),
            Box::new(Expr::Eq("b".to_string(), 2)),
        );
        assert!(expr.eval(&ctx).unwrap());
    }

    #[test]
    fn test_expr_or_short_circuit() {
        let mut ctx = HashMap::new();
        ctx.insert("a".to_string(), 1);
        ctx.insert("b".to_string(), 999);
        let expr = Expr::Or(
            Box::new(Expr::Eq("a".to_string(), 1)),
            Box::new(Expr::Eq("b".to_string(), 2)),
        );
        assert!(expr.eval(&ctx).unwrap());
    }

    #[test]
    fn test_expr_unknown_field() {
        let ctx = HashMap::new();
        assert!(Expr::Eq("missing".to_string(), 0).eval(&ctx).is_err());
    }

    // ── TemplateApplier — primitive fields ───────────────────────────────────

    #[test]
    fn test_apply_u8() {
        let data = [0x42u8];
        let b = buf(&data);
        let mut t = Template::new("T", "");
        t.add_field(u8_field("val"));
        let result = TemplateApplier::new(&b).apply(&t, 0).unwrap();
        assert_eq!(result.fields[0].value, TypedValue::U8(0x42));
    }

    #[test]
    fn test_apply_u32le() {
        let data = [0x01, 0x00, 0x00, 0x00u8];
        let b = buf(&data);
        let mut t = Template::new("T", "");
        t.add_field(u32_field("val"));
        let result = TemplateApplier::new(&b).apply(&t, 0).unwrap();
        assert_eq!(result.fields[0].value, TypedValue::U32(1));
    }

    #[test]
    fn test_apply_sequential_offset() {
        let data = [0x01u8, 0x02, 0x03, 0x04];
        let b = buf(&data);
        let mut t = Template::new("T", "");
        t.add_field(u8_field("a"));
        t.add_field(u8_field("b"));
        let result = TemplateApplier::new(&b).apply(&t, 0).unwrap();
        assert_eq!(result.fields[0].offset, 0);
        assert_eq!(result.fields[1].offset, 1);
    }

    #[test]
    fn test_apply_explicit_offset() {
        let data = [0x00u8, 0x00, 0x42, 0x00];
        let b = buf(&data);
        let mut t = Template::new("T", "");
        t.add_field(u8_field("magic").with_offset(2));
        let result = TemplateApplier::new(&b).apply(&t, 0).unwrap();
        assert_eq!(result.fields[0].value, TypedValue::U8(0x42));
    }

    // ── Conditional field ─────────────────────────────────────────────────────

    #[test]
    fn test_conditional_field_skipped() {
        let data = [0x00u8, 0xFF];
        let b = buf(&data);
        let mut t = Template::new("T", "");
        t.add_field(u8_field("flag"));
        t.add_field(u8_field("optional").with_condition(Expr::Eq("flag".to_string(), 1)));
        let result = TemplateApplier::new(&b).apply(&t, 0).unwrap();
        // flag = 0 → optional skipped
        assert_eq!(result.fields.len(), 1);
    }

    #[test]
    fn test_conditional_field_present() {
        let data = [0x01u8, 0xFF];
        let b = buf(&data);
        let mut t = Template::new("T", "");
        t.add_field(u8_field("flag"));
        t.add_field(u8_field("optional").with_condition(Expr::Eq("flag".to_string(), 1)));
        let result = TemplateApplier::new(&b).apply(&t, 0).unwrap();
        assert_eq!(result.fields.len(), 2);
        assert_eq!(result.fields[1].value, TypedValue::U8(0xFF));
    }

    // ── Array field ───────────────────────────────────────────────────────────

    #[test]
    fn test_array_field() {
        let data = [0x01u8, 0x02, 0x03];
        let b = buf(&data);
        let mut t = Template::new("T", "");
        t.add_field(FieldDef::new(
            "arr",
            TemplateType::Array {
                ty: Box::new(TemplateType::Primitive(DataType::U8)),
                count: 3,
            },
        ));
        let result = TemplateApplier::new(&b).apply(&t, 0).unwrap();
        let children = result.fields[0].children.as_ref().unwrap();
        assert_eq!(children.fields.len(), 3);
        assert_eq!(children.fields[2].value, TypedValue::U8(0x03));
    }

    // ── DynArray field ────────────────────────────────────────────────────────

    #[test]
    fn test_dynarray_field() {
        let data = [0x03u8, 0xAA, 0xBB, 0xCC];
        let b = buf(&data);
        let mut t = Template::new("T", "");
        t.add_field(u8_field("count"));
        t.add_field(FieldDef::new(
            "items",
            TemplateType::DynArray {
                ty: Box::new(TemplateType::Primitive(DataType::U8)),
                count_field: "count".to_string(),
            },
        ));
        let result = TemplateApplier::new(&b).apply(&t, 0).unwrap();
        let children = result.fields[1].children.as_ref().unwrap();
        assert_eq!(children.fields.len(), 3);
    }

    // ── Enum field ────────────────────────────────────────────────────────────

    #[test]
    fn test_enum_known_variant() {
        let data = [0x01u8];
        let b = buf(&data);
        let mut t = Template::new("T", "");
        t.add_field(FieldDef::new(
            "type",
            TemplateType::Enum {
                ty: DataType::U8,
                variants: vec![
                    ("NONE".to_string(), 0),
                    ("ELF".to_string(), 1),
                    ("PE".to_string(), 2),
                ],
            },
        ));
        let result = TemplateApplier::new(&b).apply(&t, 0).unwrap();
        assert_eq!(result.fields[0].value, TypedValue::Str("ELF".to_string()));
    }

    #[test]
    fn test_enum_unknown_variant() {
        let data = [0x99u8];
        let b = buf(&data);
        let mut t = Template::new("T", "");
        t.add_field(FieldDef::new(
            "type",
            TemplateType::Enum {
                ty: DataType::U8,
                variants: vec![("NONE".to_string(), 0)],
            },
        ));
        let result = TemplateApplier::new(&b).apply(&t, 0).unwrap();
        if let TypedValue::Str(s) = &result.fields[0].value {
            assert!(s.starts_with("unknown"));
        } else {
            panic!("expected Str");
        }
    }

    // ── String field ─────────────────────────────────────────────────────────

    #[test]
    fn test_string_field_cstr() {
        let data = b"hello\0world";
        let b = buf(data);
        let mut t = Template::new("T", "");
        t.add_field(FieldDef::new(
            "name",
            TemplateType::String {
                encoding: Encoding::Utf8,
                len: None,
            },
        ));
        let result = TemplateApplier::new(&b).apply(&t, 0).unwrap();
        assert_eq!(result.fields[0].value, TypedValue::Str("hello".to_string()));
    }

    // ── Builtin templates ─────────────────────────────────────────────────────

    #[test]
    fn test_builtin_templates_exist() {
        let map = builtin_templates();
        for name in &[
            "MZ", "PE_COFF", "ELF32", "ELF64", "ZIP", "PNG", "BMP", "JPEG", "GIF", "PDF",
        ] {
            assert!(map.contains_key(*name), "missing template: {name}");
        }
    }

    #[test]
    fn test_mz_template_apply() {
        // Minimal fake MZ header (64 bytes)
        let mut data = vec![0u8; 64];
        data[0] = b'M';
        data[1] = b'Z';
        data[60] = 0x40; // e_lfanew = 0x40
        let b = buf(&data);
        let template = builtin_templates().remove("MZ").unwrap();
        let result = TemplateApplier::new(&b).apply(&template, 0).unwrap();
        assert!(!result.fields.is_empty());
        let magic = &result.fields[0];
        assert_eq!(magic.name, "e_magic");
        if let TypedValue::Bytes(bv) = &magic.value {
            assert_eq!(&bv[..2], b"MZ");
        }
    }

    #[test]
    fn test_elf32_template_apply() {
        let mut data = vec![0u8; 52]; // ELF32 header is 52 bytes
        data[0] = 0x7F;
        data[1] = b'E';
        data[2] = b'L';
        data[3] = b'F';
        data[4] = 1; // ELFCLASS32
        let b = buf(&data);
        let template = builtin_templates().remove("ELF32").unwrap();
        let result = TemplateApplier::new(&b).apply(&template, 0).unwrap();
        assert!(!result.fields.is_empty());
    }

    // ── Template JSON serialization ───────────────────────────────────────────

    #[test]
    fn test_template_roundtrip_json() {
        let mut t = Template::new("Test", "test template");
        t.add_field(u8_field("a"));
        t.add_field(u32_field("b"));
        let json = t.to_json().unwrap();
        let t2 = Template::from_json(&json).unwrap();
        assert_eq!(t2.name, "Test");
        assert_eq!(t2.fields.len(), 2);
    }

    // ── ParsedStruct helpers ──────────────────────────────────────────────────

    #[test]
    fn test_parsed_struct_context() {
        let data = [0x07u8];
        let b = buf(&data);
        let mut t = Template::new("T", "");
        t.add_field(u8_field("version"));
        let result = TemplateApplier::new(&b).apply(&t, 0).unwrap();
        let ctx = result.context();
        assert_eq!(ctx.get("version"), Some(&7));
    }

    #[test]
    fn test_repeat_count() {
        let data = [0x01u8, 0x02, 0x03, 0x04, 0x05];
        let b = buf(&data);
        let mut t = Template::new("T", "");
        t.add_field(FieldDef::new("bytes", p(DataType::U8)).with_repeat(RepeatSpec::Count(5)));
        let result = TemplateApplier::new(&b).apply(&t, 0).unwrap();
        assert_eq!(result.fields.len(), 5);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// BitfieldDef / BitfieldValue
// ─────────────────────────────────────────────────────────────────────────────

/// A single bit-field within an integer value.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BitfieldDef {
    /// Name of the bit field.
    pub name: String,
    /// Zero-based start bit (LSB = 0).
    pub start_bit: u8,
    /// Number of bits (1..=64).
    pub bit_count: u8,
    pub comment: String,
}

impl BitfieldDef {
    /// Create a new bitfield definition.
    #[must_use]
    pub fn new(name: impl Into<String>, start_bit: u8, bit_count: u8) -> Self {
        Self {
            name: name.into(),
            start_bit,
            bit_count,
            comment: String::new(),
        }
    }

    /// Set a comment.
    #[must_use]
    pub fn with_comment(mut self, comment: impl Into<String>) -> Self {
        self.comment = comment.into();
        self
    }

    /// Extract this field's value from `raw`.
    #[must_use]
    pub const fn extract(&self, raw: u64) -> u64 {
        let mask = if self.bit_count >= 64 {
            u64::MAX
        } else {
            (1u64 << self.bit_count) - 1
        };
        (raw >> self.start_bit) & mask
    }
}

/// The result of parsing one bitfield.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BitfieldValue {
    pub name: String,
    pub value: u64,
    pub start_bit: u8,
    pub bit_count: u8,
}

/// A collection of bit fields extracted from a single integer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BitfieldStruct {
    pub name: String,
    /// Underlying raw integer value.
    pub raw: u64,
    pub fields: Vec<BitfieldValue>,
}

impl BitfieldStruct {
    /// Extract all bit fields from `raw`.
    #[must_use]
    pub fn extract(name: impl Into<String>, raw: u64, defs: &[BitfieldDef]) -> Self {
        let fields = defs
            .iter()
            .map(|d| BitfieldValue {
                name: d.name.clone(),
                value: d.extract(raw),
                start_bit: d.start_bit,
                bit_count: d.bit_count,
            })
            .collect();
        Self {
            name: name.into(),
            raw,
            fields,
        }
    }

    /// Look up a field value by name.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<u64> {
        self.fields.iter().find(|f| f.name == name).map(|f| f.value)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TemplateRegistry — a simple registry of named templates
// (The richer TemplateLibrary with categories/tags/export lives in
//  the `template_library` sub-module.)
// ─────────────────────────────────────────────────────────────────────────────

/// A named registry of `Template` objects.
///
/// For the full-featured library with categories, tags, search, and export
/// see [`template_library::TemplateLibrary`].
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct TemplateRegistry {
    templates: HashMap<String, Template>,
}

impl TemplateRegistry {
    /// Create an empty library.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a library pre-loaded with all built-in templates.
    #[must_use]
    pub fn with_builtins() -> Self {
        Self {
            templates: builtin_templates(),
        }
    }

    /// Register a template.
    pub fn register(&mut self, template: Template) {
        self.templates.insert(template.name.clone(), template);
    }

    /// Look up a template by name.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&Template> {
        self.templates.get(name)
    }

    /// Remove a template by name.
    pub fn remove(&mut self, name: &str) -> Option<Template> {
        self.templates.remove(name)
    }

    /// Return all registered template names.
    #[must_use]
    pub fn names(&self) -> Vec<&str> {
        let mut names: Vec<&str> = self.templates.keys().map(String::as_str).collect();
        names.sort_unstable();
        names
    }

    /// Number of templates in the library.
    #[must_use]
    pub fn len(&self) -> usize {
        self.templates.len()
    }

    /// Returns `true` if the library is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.templates.is_empty()
    }

    /// Apply a named template to `buf` starting at `base_offset`.
    ///
    /// # Errors
    /// Returns `TemplateError::NotFound` if the template does not exist,
    /// or propagates `TemplateApplier` errors.
    pub fn apply(
        &self,
        name: &str,
        buf: &HexBuffer,
        base_offset: usize,
    ) -> Result<ParsedStruct, TemplateError> {
        let tmpl = self
            .get(name)
            .ok_or_else(|| TemplateError::NotFound(name.to_string()))?;
        TemplateApplier::new(buf).apply(tmpl, base_offset)
    }

    /// Serialize the whole library to JSON.
    ///
    /// # Errors
    /// Returns `TemplateError::Serde` on failure.
    pub fn to_json(&self) -> Result<String, TemplateError> {
        serde_json::to_string_pretty(&self.templates).map_err(TemplateError::Serde)
    }

    /// Deserialize a library from JSON.
    ///
    /// # Errors
    /// Returns `TemplateError::Serde` on failure.
    pub fn from_json(json: &str) -> Result<Self, TemplateError> {
        let templates: HashMap<String, Template> =
            serde_json::from_str(json).map_err(TemplateError::Serde)?;
        Ok(Self { templates })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ParsedStructPrinter — human-readable output
// ─────────────────────────────────────────────────────────────────────────────

/// Renders a `ParsedStruct` as indented text.
pub struct ParsedStructPrinter {
    pub indent_str: String,
}

impl ParsedStructPrinter {
    /// Create with the default 2-space indent.
    #[must_use]
    pub fn new() -> Self {
        Self {
            indent_str: "  ".to_string(),
        }
    }

    /// Create with a custom indent string.
    #[must_use]
    pub fn with_indent(indent: impl Into<String>) -> Self {
        Self {
            indent_str: indent.into(),
        }
    }

    /// Render `ps` to a string.
    #[must_use]
    pub fn render(&self, ps: &ParsedStruct) -> String {
        let mut out = String::new();
        self.render_struct(ps, &mut out, 0);
        out
    }

    fn render_struct(&self, ps: &ParsedStruct, out: &mut String, depth: usize) {
        let indent = self.indent_str.repeat(depth);
        out.push_str(&format!("{indent}struct {} {{\n", ps.name));
        for field in &ps.fields {
            self.render_field(field, out, depth + 1);
        }
        out.push_str(&format!("{indent}}}\n"));
    }

    fn render_field(&self, f: &ParsedField, out: &mut String, depth: usize) {
        let indent = self.indent_str.repeat(depth);
        if let Some(ref children) = f.children {
            out.push_str(&format!(
                "{indent}+0x{:04X}  {} (size={})\n",
                f.offset, f.name, f.size
            ));
            self.render_struct(children, out, depth + 1);
        } else {
            out.push_str(&format!(
                "{indent}+0x{:04X}  {} = {}  (size={})\n",
                f.offset, f.name, f.value, f.size
            ));
        }
    }
}

impl Default for ParsedStructPrinter {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Extended template library — more formats
// ─────────────────────────────────────────────────────────────────────────────

/// Returns a RIFF/WAV chunk header template.
#[must_use]
pub fn template_riff_chunk() -> Template {
    let mut t = Template::new("RIFF_CHUNK", "RIFF chunk header");
    t.add_field(bytes_field("ChunkID", 4).with_comment("'RIFF', 'fmt ', 'data', etc."));
    t.add_field(u32_field("ChunkSize").with_comment("size of chunk data"));
    t
}

/// Returns a WAV file header template.
#[must_use]
pub fn template_wav() -> Template {
    let mut t = Template::new("WAV", "WAV RIFF/WAVE file header");
    // RIFF chunk
    t.add_field(bytes_field("RiffID", 4).with_comment("'RIFF'"));
    t.add_field(u32_field("RiffSize"));
    t.add_field(bytes_field("WaveID", 4).with_comment("'WAVE'"));
    // fmt chunk
    t.add_field(bytes_field("FmtID", 4).with_comment("'fmt '"));
    t.add_field(u32_field("FmtSize").with_comment("16 for PCM"));
    t.add_field(u16_field("AudioFormat").with_comment("1 = PCM"));
    t.add_field(u16_field("NumChannels"));
    t.add_field(u32_field("SampleRate"));
    t.add_field(u32_field("ByteRate"));
    t.add_field(u16_field("BlockAlign"));
    t.add_field(u16_field("BitsPerSample"));
    // data chunk header
    t.add_field(bytes_field("DataID", 4).with_comment("'data'"));
    t.add_field(u32_field("DataSize"));
    t
}

/// Returns an ELF Program Header Entry (32-bit) template.
#[must_use]
pub fn template_elf32_phdr() -> Template {
    let mut t = Template::new("ELF32_PHDR", "ELF 32-bit Program Header Entry");
    t.add_field(u32_field("p_type").with_comment("segment type"));
    t.add_field(u32_field("p_offset").with_comment("file offset"));
    t.add_field(u32_field("p_vaddr").with_comment("virtual address"));
    t.add_field(u32_field("p_paddr").with_comment("physical address"));
    t.add_field(u32_field("p_filesz").with_comment("size in file"));
    t.add_field(u32_field("p_memsz").with_comment("size in memory"));
    t.add_field(u32_field("p_flags").with_comment("PF_X|PF_W|PF_R"));
    t.add_field(u32_field("p_align").with_comment("alignment"));
    t
}

/// Returns an ELF Program Header Entry (64-bit) template.
#[must_use]
pub fn template_elf64_phdr() -> Template {
    let mut t = Template::new("ELF64_PHDR", "ELF 64-bit Program Header Entry");
    t.add_field(u32_field("p_type"));
    t.add_field(u32_field("p_flags"));
    t.add_field(u64_field("p_offset"));
    t.add_field(u64_field("p_vaddr"));
    t.add_field(u64_field("p_paddr"));
    t.add_field(u64_field("p_filesz"));
    t.add_field(u64_field("p_memsz"));
    t.add_field(u64_field("p_align"));
    t
}

/// Returns an ELF Section Header Entry (32-bit) template.
#[must_use]
pub fn template_elf32_shdr() -> Template {
    let mut t = Template::new("ELF32_SHDR", "ELF 32-bit Section Header Entry");
    t.add_field(u32_field("sh_name").with_comment("offset into .shstrtab"));
    t.add_field(u32_field("sh_type"));
    t.add_field(u32_field("sh_flags"));
    t.add_field(u32_field("sh_addr"));
    t.add_field(u32_field("sh_offset"));
    t.add_field(u32_field("sh_size"));
    t.add_field(u32_field("sh_link"));
    t.add_field(u32_field("sh_info"));
    t.add_field(u32_field("sh_addralign"));
    t.add_field(u32_field("sh_entsize"));
    t
}

/// Returns a PE Optional Header (PE32) template.
#[must_use]
pub fn template_pe_optional_header() -> Template {
    let mut t = Template::new("PE_OPT_HEADER", "PE32 Optional Header");
    t.add_field(u16_field("Magic").with_comment("0x010B = PE32"));
    t.add_field(u8_field("MajorLinkerVersion"));
    t.add_field(u8_field("MinorLinkerVersion"));
    t.add_field(u32_field("SizeOfCode"));
    t.add_field(u32_field("SizeOfInitializedData"));
    t.add_field(u32_field("SizeOfUninitializedData"));
    t.add_field(u32_field("AddressOfEntryPoint"));
    t.add_field(u32_field("BaseOfCode"));
    t.add_field(u32_field("BaseOfData"));
    t.add_field(u32_field("ImageBase"));
    t.add_field(u32_field("SectionAlignment"));
    t.add_field(u32_field("FileAlignment"));
    t.add_field(u16_field("MajorOperatingSystemVersion"));
    t.add_field(u16_field("MinorOperatingSystemVersion"));
    t.add_field(u16_field("MajorImageVersion"));
    t.add_field(u16_field("MinorImageVersion"));
    t.add_field(u16_field("MajorSubsystemVersion"));
    t.add_field(u16_field("MinorSubsystemVersion"));
    t.add_field(u32_field("Win32VersionValue"));
    t.add_field(u32_field("SizeOfImage"));
    t.add_field(u32_field("SizeOfHeaders"));
    t.add_field(u32_field("CheckSum"));
    t.add_field(u16_field("Subsystem"));
    t.add_field(u16_field("DllCharacteristics"));
    t.add_field(u32_field("SizeOfStackReserve"));
    t.add_field(u32_field("SizeOfStackCommit"));
    t.add_field(u32_field("SizeOfHeapReserve"));
    t.add_field(u32_field("SizeOfHeapCommit"));
    t.add_field(u32_field("LoaderFlags"));
    t.add_field(u32_field("NumberOfRvaAndSizes"));
    t
}

/// Returns a PE Section Header template.
#[must_use]
pub fn template_pe_section_header() -> Template {
    let mut t = Template::new(
        "PE_SECTION_HEADER",
        "PE Section Header (IMAGE_SECTION_HEADER)",
    );
    t.add_field(bytes_field("Name", 8).with_comment("UTF-8 section name, padded with NUL"));
    t.add_field(u32_field("VirtualSize").with_comment("size when loaded into memory"));
    t.add_field(u32_field("VirtualAddress").with_comment("RVA of the section"));
    t.add_field(u32_field("SizeOfRawData"));
    t.add_field(u32_field("PointerToRawData"));
    t.add_field(u32_field("PointerToRelocations"));
    t.add_field(u32_field("PointerToLinenumbers"));
    t.add_field(u16_field("NumberOfRelocations"));
    t.add_field(u16_field("NumberOfLinenumbers"));
    t.add_field(u32_field("Characteristics").with_comment("IMAGE_SCN_* flags"));
    t
}

/// Returns an MP4 Box / Atom header template.
#[must_use]
pub fn template_mp4_box() -> Template {
    let mut t = Template::new("MP4_BOX", "MP4 / ISO BMFF box header");
    t.add_field(
        FieldDef::new("size", p(DataType::U32Be)).with_comment("box size including header"),
    );
    t.add_field(bytes_field("type", 4).with_comment("four-character code e.g. 'ftyp'"));
    t
}

/// Returns a JPEG DQT (Define Quantization Table) marker template.
#[must_use]
pub fn template_jpeg_dqt() -> Template {
    let mut t = Template::new("JPEG_DQT", "JPEG Define Quantization Table marker");
    t.add_field(bytes_field("Marker", 2).with_comment("\\xFF\\xDB"));
    t.add_field(FieldDef::new("Length", p(DataType::U16Be)));
    t.add_field(u8_field("PrecisionAndId").with_comment("bits 7-4 = precision, 3-0 = table id"));
    t
}

/// Returns a PNG chunk header template.
#[must_use]
pub fn template_png_chunk() -> Template {
    let mut t = Template::new("PNG_CHUNK", "PNG chunk header");
    t.add_field(FieldDef::new("Length", p(DataType::U32Be)).with_comment("length of chunk data"));
    t.add_field(bytes_field("Type", 4).with_comment("chunk type (IHDR, IDAT, IEND, ...)"));
    t
}

/// Returns a Mach-O header template (32-bit).
#[must_use]
pub fn template_macho32() -> Template {
    let mut t = Template::new("MACHO32", "Mach-O 32-bit header");
    t.add_field(u32_field("magic").with_comment("0xFEEDFACE (BE) or 0xCEFAEDFE (LE)"));
    t.add_field(u32_field("cputype"));
    t.add_field(u32_field("cpusubtype"));
    t.add_field(u32_field("filetype"));
    t.add_field(u32_field("ncmds").with_comment("number of load commands"));
    t.add_field(u32_field("sizeofcmds").with_comment("total size of load commands"));
    t.add_field(u32_field("flags"));
    t
}

/// Returns a Mach-O header template (64-bit).
#[must_use]
pub fn template_macho64() -> Template {
    let mut t = Template::new("MACHO64", "Mach-O 64-bit header");
    t.add_field(u32_field("magic").with_comment("0xFEEDFACF (BE) or 0xCFFAEDFE (LE)"));
    t.add_field(u32_field("cputype"));
    t.add_field(u32_field("cpusubtype"));
    t.add_field(u32_field("filetype"));
    t.add_field(u32_field("ncmds"));
    t.add_field(u32_field("sizeofcmds"));
    t.add_field(u32_field("flags"));
    t.add_field(u32_field("reserved"));
    t
}

// ─────────────────────────────────────────────────────────────────────────────
// TemplateApplier — cursor-tracking extensions
// ─────────────────────────────────────────────────────────────────────────────

impl TemplateApplier<'_> {
    /// Apply a template and return the byte offset just past the last parsed field.
    ///
    /// # Errors
    /// Propagates any `TemplateError`.
    pub fn apply_with_end(
        &self,
        template: &Template,
        base_offset: usize,
    ) -> Result<(ParsedStruct, usize), TemplateError> {
        let parsed = self.apply(template, base_offset)?;
        let end = parsed
            .fields
            .iter()
            .map(|f| f.offset + f.size)
            .max()
            .unwrap_or(base_offset);
        Ok((parsed, end))
    }

    /// Read a raw `u64` field value by name from the first level of `template`.
    ///
    /// # Errors
    /// Returns `TemplateError::NotFound` if the field is missing.
    pub fn read_u64(
        &self,
        template: &Template,
        base_offset: usize,
        field_name: &str,
    ) -> Result<u64, TemplateError> {
        let parsed = self.apply(template, base_offset)?;
        parsed.field_as_u64(field_name).ok_or_else(|| {
            TemplateError::Field(
                field_name.to_string(),
                "field not found or not convertible to u64".to_string(),
            )
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TemplateValidator — check a parsed struct against constraints
// ─────────────────────────────────────────────────────────────────────────────

/// A validation rule for a parsed struct field.
#[derive(Debug, Clone)]
pub struct ValidationRule {
    /// Field name to validate.
    pub field: String,
    /// Expected exact value, if any.
    pub expected_value: Option<u64>,
    /// Expected exact bytes (for Bytes fields), if any.
    pub expected_bytes: Option<Vec<u8>>,
    /// Minimum value (inclusive), if any.
    pub min_value: Option<u64>,
    /// Maximum value (inclusive), if any.
    pub max_value: Option<u64>,
    pub description: String,
}

impl ValidationRule {
    /// Create a rule that checks a field equals an exact value.
    #[must_use]
    pub fn equals_u64(field: impl Into<String>, value: u64, desc: impl Into<String>) -> Self {
        Self {
            field: field.into(),
            expected_value: Some(value),
            expected_bytes: None,
            min_value: None,
            max_value: None,
            description: desc.into(),
        }
    }

    /// Create a rule that checks a field equals exact bytes.
    #[must_use]
    pub fn equals_bytes(field: impl Into<String>, bytes: Vec<u8>, desc: impl Into<String>) -> Self {
        Self {
            field: field.into(),
            expected_value: None,
            expected_bytes: Some(bytes),
            min_value: None,
            max_value: None,
            description: desc.into(),
        }
    }

    /// Create a range rule.
    #[must_use]
    pub fn in_range(field: impl Into<String>, min: u64, max: u64, desc: impl Into<String>) -> Self {
        Self {
            field: field.into(),
            expected_value: None,
            expected_bytes: None,
            min_value: Some(min),
            max_value: Some(max),
            description: desc.into(),
        }
    }
}

/// Result of validating a single rule.
#[derive(Debug, Clone)]
pub struct ValidationResult {
    pub rule: String,
    pub passed: bool,
    pub message: String,
}

/// Validates a `ParsedStruct` against a set of rules.
pub struct TemplateValidator {
    rules: Vec<ValidationRule>,
}

impl TemplateValidator {
    /// Create a validator with no rules.
    #[must_use]
    pub const fn new() -> Self {
        Self { rules: Vec::new() }
    }

    /// Add a rule.
    pub fn add_rule(&mut self, rule: ValidationRule) {
        self.rules.push(rule);
    }

    /// Validate `ps` against all rules and return results.
    #[must_use]
    pub fn validate(&self, ps: &ParsedStruct) -> Vec<ValidationResult> {
        self.rules
            .iter()
            .map(|rule| self.apply_rule(rule, ps))
            .collect()
    }

    fn apply_rule(&self, rule: &ValidationRule, ps: &ParsedStruct) -> ValidationResult {
        let field_opt = ps.fields.iter().find(|f| f.name == rule.field);
        let Some(field) = field_opt else {
            return ValidationResult {
                rule: rule.description.clone(),
                passed: false,
                message: format!("field '{}' not found", rule.field),
            };
        };

        // Check exact bytes
        if let Some(ref expected) = rule.expected_bytes {
            let ok = match &field.value {
                TypedValue::Bytes(b) => b == expected,
                _ => false,
            };
            return ValidationResult {
                rule: rule.description.clone(),
                passed: ok,
                message: if ok {
                    "bytes match".to_string()
                } else {
                    format!("bytes mismatch in field '{}'", rule.field)
                },
            };
        }

        // Check exact u64
        if let Some(expected) = rule.expected_value {
            let actual = typed_value_to_u64(&field.value);
            let ok = actual == Some(expected);
            return ValidationResult {
                rule: rule.description.clone(),
                passed: ok,
                message: if ok {
                    format!("value = {expected}")
                } else {
                    format!("expected {expected}, got {:?}", actual.unwrap_or(u64::MAX))
                },
            };
        }

        // Check range
        if rule.min_value.is_some() || rule.max_value.is_some() {
            if let Some(actual) = typed_value_to_u64(&field.value) {
                let above_min = rule.min_value.is_none_or(|m| actual >= m);
                let below_max = rule.max_value.is_none_or(|m| actual <= m);
                let ok = above_min && below_max;
                return ValidationResult {
                    rule: rule.description.clone(),
                    passed: ok,
                    message: if ok {
                        format!("value {actual} in range")
                    } else {
                        format!(
                            "value {actual} out of range [{}, {}]",
                            rule.min_value.unwrap_or(0),
                            rule.max_value.unwrap_or(u64::MAX),
                        )
                    },
                };
            }
            return ValidationResult {
                rule: rule.description.clone(),
                passed: false,
                message: "field value not convertible to u64 for range check".to_string(),
            };
        }

        ValidationResult {
            rule: rule.description.clone(),
            passed: true,
            message: "no constraint".to_string(),
        }
    }

    /// Returns `true` if all validation results passed.
    #[must_use]
    pub fn all_pass(results: &[ValidationResult]) -> bool {
        results.iter().all(|r| r.passed)
    }
}

impl Default for TemplateValidator {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Additional tests for the expanded API
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests_expanded {
    use super::*;

    fn buf(data: &[u8]) -> HexBuffer {
        HexBuffer::new(data.to_vec())
    }

    // ── BitfieldDef ───────────────────────────────────────────────────────────

    #[test]
    fn test_bitfield_extract_low_bits() {
        let d = BitfieldDef::new("low3", 0, 3);
        assert_eq!(d.extract(0b1011_1010), 0b010);
    }

    #[test]
    fn test_bitfield_extract_high_bits() {
        let d = BitfieldDef::new("high4", 4, 4);
        assert_eq!(d.extract(0xAB), 0xA);
    }

    #[test]
    fn test_bitfield_struct_extract() {
        let defs = vec![
            BitfieldDef::new("present", 0, 1),
            BitfieldDef::new("rw", 1, 1),
            BitfieldDef::new("user", 2, 1),
        ];
        let bs = BitfieldStruct::extract("pte_flags", 0b111, &defs);
        assert_eq!(bs.get("present"), Some(1));
        assert_eq!(bs.get("rw"), Some(1));
        assert_eq!(bs.get("user"), Some(1));
    }

    #[test]
    fn test_bitfield_struct_partial() {
        let defs = vec![BitfieldDef::new("bits5to2", 2, 4)];
        let bs = BitfieldStruct::extract("x", 0b1111_1100, &defs);
        assert_eq!(bs.get("bits5to2"), Some(0b1111));
    }

    // ── TemplateRegistry ───────────────────────────────────────────────────────

    #[test]
    fn test_library_with_builtins() {
        let lib = TemplateRegistry::with_builtins();
        assert!(lib.len() >= 10);
        assert!(lib.get("MZ").is_some());
        assert!(lib.get("ELF64").is_some());
    }

    #[test]
    fn test_library_register_and_get() {
        let mut lib = TemplateRegistry::new();
        let t = Template::new("FOO", "test");
        lib.register(t);
        assert!(lib.get("FOO").is_some());
        assert_eq!(lib.len(), 1);
    }

    #[test]
    fn test_library_remove() {
        let mut lib = TemplateRegistry::with_builtins();
        let removed = lib.remove("PDF");
        assert!(removed.is_some());
        assert!(lib.get("PDF").is_none());
    }

    #[test]
    fn test_library_apply_mz() {
        let mut data = vec![0u8; 64];
        data[0] = b'M';
        data[1] = b'Z';
        data[60] = 0x40;
        let b = buf(&data);
        let lib = TemplateRegistry::with_builtins();
        let result = lib.apply("MZ", &b, 0).unwrap();
        assert!(!result.fields.is_empty());
    }

    #[test]
    fn test_library_apply_not_found() {
        let lib = TemplateRegistry::new();
        let b = buf(&[0u8; 8]);
        assert!(lib.apply("NONEXISTENT", &b, 0).is_err());
    }

    #[test]
    fn test_library_names_sorted() {
        let lib = TemplateRegistry::with_builtins();
        let names = lib.names();
        let mut sorted = names.clone();
        sorted.sort_unstable();
        assert_eq!(names, sorted);
    }

    // ── Extended templates ────────────────────────────────────────────────────

    #[test]
    fn test_wav_template_fields() {
        let t = template_wav();
        assert!(t.fields.len() >= 13);
        assert_eq!(t.fields[0].name, "RiffID");
    }

    #[test]
    fn test_elf32_phdr_fields() {
        let t = template_elf32_phdr();
        assert_eq!(t.fields.len(), 8);
    }

    #[test]
    fn test_elf64_phdr_fields() {
        let t = template_elf64_phdr();
        assert_eq!(t.fields.len(), 8);
    }

    #[test]
    fn test_pe_section_header_fields() {
        let t = template_pe_section_header();
        assert_eq!(t.fields[0].name, "Name");
        assert_eq!(t.fields.len(), 10);
    }

    #[test]
    fn test_pe_optional_header_fields() {
        let t = template_pe_optional_header();
        assert_eq!(t.fields[0].name, "Magic");
        assert!(t.fields.len() >= 28);
    }

    #[test]
    fn test_macho32_template_fields() {
        let t = template_macho32();
        assert_eq!(t.fields.len(), 7);
        assert_eq!(t.fields[0].name, "magic");
    }

    #[test]
    fn test_macho64_template_fields() {
        let t = template_macho64();
        assert_eq!(t.fields.len(), 8);
    }

    #[test]
    fn test_mp4_box_template() {
        let t = template_mp4_box();
        assert_eq!(t.fields[0].name, "size");
        assert_eq!(t.fields[1].name, "type");
    }

    // ── ParsedStructPrinter ───────────────────────────────────────────────────

    #[test]
    fn test_printer_renders_fields() {
        let mut data = vec![0u8; 8];
        data[0] = 0x42;
        let b = buf(&data);
        let mut t = Template::new("T", "");
        t.add_field(FieldDef::new(
            "val",
            TemplateType::Primitive(rustre_hex::DataType::U8),
        ));
        let result = TemplateApplier::new(&b).apply(&t, 0).unwrap();
        let printer = ParsedStructPrinter::new();
        let output = printer.render(&result);
        assert!(output.contains("val"));
        assert!(output.contains("66")); // 0x42 = 66
    }

    #[test]
    fn test_printer_custom_indent() {
        let data = [0x01u8];
        let b = buf(&data);
        let mut t = Template::new("T", "");
        t.add_field(FieldDef::new(
            "x",
            TemplateType::Primitive(rustre_hex::DataType::U8),
        ));
        let result = TemplateApplier::new(&b).apply(&t, 0).unwrap();
        let printer = ParsedStructPrinter::with_indent("    ");
        let output = printer.render(&result);
        assert!(output.contains("    "));
    }

    // ── TemplateApplier extensions ────────────────────────────────────────────

    #[test]
    fn test_apply_with_end() {
        let data = [0x01u8, 0x02, 0x03, 0x04];
        let b = buf(&data);
        let mut t = Template::new("T", "");
        t.add_field(FieldDef::new(
            "a",
            TemplateType::Primitive(rustre_hex::DataType::U16Le),
        ));
        t.add_field(FieldDef::new(
            "b",
            TemplateType::Primitive(rustre_hex::DataType::U16Le),
        ));
        let applier = TemplateApplier::new(&b);
        let (result, end) = applier.apply_with_end(&t, 0).unwrap();
        assert_eq!(end, 4);
        assert_eq!(result.fields.len(), 2);
    }

    #[test]
    fn test_read_u64_field() {
        let data = [0x05u8, 0x00, 0x00, 0x00];
        let b = buf(&data);
        let mut t = Template::new("T", "");
        t.add_field(FieldDef::new(
            "count",
            TemplateType::Primitive(rustre_hex::DataType::U32Le),
        ));
        let applier = TemplateApplier::new(&b);
        let v = applier.read_u64(&t, 0, "count").unwrap();
        assert_eq!(v, 5);
    }

    // ── TemplateValidator ─────────────────────────────────────────────────────

    #[test]
    fn test_validator_bytes_match() {
        let data = [b'M', b'Z', 0, 0];
        let b = buf(&data);
        let mut t = Template::new("T", "");
        t.add_field(FieldDef::new(
            "magic",
            TemplateType::Primitive(rustre_hex::DataType::Bytes(2)),
        ));
        let result = TemplateApplier::new(&b).apply(&t, 0).unwrap();
        let mut v = TemplateValidator::new();
        v.add_rule(ValidationRule::equals_bytes(
            "magic",
            b"MZ".to_vec(),
            "MZ signature",
        ));
        let results = v.validate(&result);
        assert!(results[0].passed);
    }

    #[test]
    fn test_validator_u64_match() {
        let data = [0x01u8];
        let b = buf(&data);
        let mut t = Template::new("T", "");
        t.add_field(FieldDef::new(
            "v",
            TemplateType::Primitive(rustre_hex::DataType::U8),
        ));
        let result = TemplateApplier::new(&b).apply(&t, 0).unwrap();
        let mut v = TemplateValidator::new();
        v.add_rule(ValidationRule::equals_u64("v", 1, "must be 1"));
        let results = v.validate(&result);
        assert!(results[0].passed);
    }

    #[test]
    fn test_validator_range_pass() {
        let data = [0x10u8];
        let b = buf(&data);
        let mut t = Template::new("T", "");
        t.add_field(FieldDef::new(
            "v",
            TemplateType::Primitive(rustre_hex::DataType::U8),
        ));
        let result = TemplateApplier::new(&b).apply(&t, 0).unwrap();
        let mut v = TemplateValidator::new();
        v.add_rule(ValidationRule::in_range("v", 1, 255, "non-zero"));
        let results = v.validate(&result);
        assert!(results[0].passed);
    }

    #[test]
    fn test_validator_field_not_found() {
        let data = [0x00u8];
        let b = buf(&data);
        let t = Template::new("T", "");
        let result = TemplateApplier::new(&b).apply(&t, 0).unwrap();
        let mut v = TemplateValidator::new();
        v.add_rule(ValidationRule::equals_u64("missing", 0, "missing field"));
        let results = v.validate(&result);
        assert!(!results[0].passed);
    }

    #[test]
    fn test_validator_all_pass() {
        let results = vec![
            ValidationResult {
                rule: "r1".into(),
                passed: true,
                message: String::new(),
            },
            ValidationResult {
                rule: "r2".into(),
                passed: true,
                message: String::new(),
            },
        ];
        assert!(TemplateValidator::all_pass(&results));
    }

    #[test]
    fn test_validator_not_all_pass() {
        let results = vec![
            ValidationResult {
                rule: "r1".into(),
                passed: true,
                message: String::new(),
            },
            ValidationResult {
                rule: "r2".into(),
                passed: false,
                message: "fail".into(),
            },
        ];
        assert!(!TemplateValidator::all_pass(&results));
    }

    // ── TemplateLibrary JSON ──────────────────────────────────────────────────

    #[test]
    fn test_library_json_roundtrip() {
        let lib = TemplateRegistry::with_builtins();
        let json = lib.to_json().unwrap();
        let lib2 = TemplateRegistry::from_json(&json).unwrap();
        assert_eq!(lib.len(), lib2.len());
    }

    // ── Struct template nesting ───────────────────────────────────────────────

    #[test]
    fn test_nested_struct_field() {
        let data = [0x01u8, 0x02, 0x03, 0x04];
        let b = buf(&data);
        let inner_fields = vec![
            FieldDef::new("x", TemplateType::Primitive(rustre_hex::DataType::U8)),
            FieldDef::new("y", TemplateType::Primitive(rustre_hex::DataType::U8)),
        ];
        let mut t = Template::new("T", "");
        t.add_field(FieldDef::new("point", TemplateType::Struct(inner_fields)));
        t.add_field(FieldDef::new(
            "z",
            TemplateType::Primitive(rustre_hex::DataType::U8),
        ));
        let result = TemplateApplier::new(&b).apply(&t, 0).unwrap();
        assert_eq!(result.fields.len(), 2);
        let children = result.fields[0].children.as_ref().unwrap();
        assert_eq!(children.fields.len(), 2);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TemplateField — lightweight flat representation for display/diff
// ─────────────────────────────────────────────────────────────────────────────

/// A flat record of a single field parsed from binary data.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TemplateField {
    /// Dotted path of the field (e.g. `"header.magic"`).
    pub path: String,
    /// Display name of the innermost field.
    pub name: String,
    /// Byte offset inside the buffer.
    pub offset: usize,
    /// Byte length.
    pub size: usize,
    /// Decoded value as a human-readable string.
    pub display: String,
    /// Optional comment from the template.
    pub comment: Option<String>,
    /// Nesting depth (0 = top-level).
    pub depth: usize,
}

impl TemplateField {
    /// Create a new field record.
    #[must_use]
    pub fn new(
        path: impl Into<String>,
        name: impl Into<String>,
        offset: usize,
        size: usize,
        display: impl Into<String>,
    ) -> Self {
        Self {
            path: path.into(),
            name: name.into(),
            offset,
            size,
            display: display.into(),
            comment: None,
            depth: 0,
        }
    }

    /// Attach a comment.
    #[must_use]
    pub fn with_comment(mut self, comment: impl Into<String>) -> Self {
        self.comment = Some(comment.into());
        self
    }

    /// Attach a depth.
    #[must_use]
    pub const fn with_depth(mut self, depth: usize) -> Self {
        self.depth = depth;
        self
    }

    /// Format as a one-liner for display.
    #[must_use]
    pub fn format_line(&self) -> String {
        let indent = "  ".repeat(self.depth);
        let comment_part = self
            .comment
            .as_deref()
            .map(|c| format!("  // {c}"))
            .unwrap_or_default();
        format!(
            "{indent}{:40} @{:08X}  +{:4}  {}{}",
            self.name, self.offset, self.size, self.display, comment_part
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// FlattenVisitor — converts a ParsedStruct tree into a Vec<TemplateField>
// ─────────────────────────────────────────────────────────────────────────────

/// Flatten a `ParsedStruct` tree into a linear list of [`TemplateField`]s.
#[must_use]
pub fn flatten_parsed(parsed: &ParsedStruct) -> Vec<TemplateField> {
    let mut out = Vec::new();
    flatten_parsed_inner(parsed, "", 0, &mut out);
    out
}

fn flatten_parsed_inner(
    parsed: &ParsedStruct,
    prefix: &str,
    depth: usize,
    out: &mut Vec<TemplateField>,
) {
    for pf in &parsed.fields {
        let path = if prefix.is_empty() {
            pf.name.clone()
        } else {
            format!("{prefix}.{}", pf.name)
        };
        let display = match &pf.value {
            TypedValue::U8(v) => format!("{v:#04X}"),
            TypedValue::U16(v) => format!("{v:#06X}"),
            TypedValue::U32(v) => format!("{v:#010X}"),
            TypedValue::U64(v) => format!("{v:#018X}"),
            TypedValue::I8(v) => format!("{v}"),
            TypedValue::I16(v) => format!("{v}"),
            TypedValue::I32(v) => format!("{v}"),
            TypedValue::I64(v) => format!("{v}"),
            TypedValue::F32(v) => format!("{v:.6}"),
            TypedValue::F64(v) => format!("{v:.6}"),
            TypedValue::Bytes(b) => {
                let preview: String = b
                    .iter()
                    .take(16)
                    .map(|x| format!("{x:02X}"))
                    .collect::<Vec<_>>()
                    .join(" ");
                if b.len() > 16 {
                    format!("{preview} ...")
                } else {
                    preview
                }
            }
            TypedValue::Str(s) => format!("{s:?}"),
        };
        let tf = TemplateField::new(&path, &pf.name, pf.offset, pf.size, display).with_depth(depth);
        out.push(tf);
        if let Some(children) = &pf.children {
            flatten_parsed_inner(children, &path, depth + 1, out);
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TemplateDiff — diff two ParsedStruct results
// ─────────────────────────────────────────────────────────────────────────────

/// A single difference between two parsed results.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum DiffEntry {
    /// Field present only in the first parse.
    OnlyLeft(TemplateField),
    /// Field present only in the second parse.
    OnlyRight(TemplateField),
    /// Field present in both but with different values.
    Changed {
        /// Field as seen in the first parse.
        left: TemplateField,
        /// Field as seen in the second parse.
        right: TemplateField,
    },
}

impl DiffEntry {
    /// Return the field path this diff entry relates to.
    #[must_use]
    pub fn path(&self) -> &str {
        match self {
            DiffEntry::OnlyLeft(f) | DiffEntry::OnlyRight(f) => &f.path,
            DiffEntry::Changed { left, .. } => &left.path,
        }
    }

    /// Whether the diff is a value change (both sides present).
    #[must_use]
    pub const fn is_change(&self) -> bool {
        matches!(self, DiffEntry::Changed { .. })
    }
}

/// Diff two [`ParsedStruct`] trees, returning a list of differences.
#[must_use]
pub fn diff_parsed(left: &ParsedStruct, right: &ParsedStruct) -> Vec<DiffEntry> {
    let lf = flatten_parsed(left);
    let rf = flatten_parsed(right);

    let mut right_map: HashMap<String, TemplateField> =
        rf.iter().map(|f| (f.path.clone(), f.clone())).collect();

    let mut diffs = Vec::with_capacity(lf.len());
    // Check all paths in left
    for lfield in &lf {
        if let Some(rfield) = right_map.remove(&lfield.path) {
            if lfield.display != rfield.display || lfield.offset != rfield.offset {
                diffs.push(DiffEntry::Changed {
                    left: lfield.clone(),
                    right: rfield,
                });
            }
        } else {
            diffs.push(DiffEntry::OnlyLeft(lfield.clone()));
        }
    }
    // Remaining right paths
    for rfield in rf {
        if right_map.contains_key(&rfield.path) {
            diffs.push(DiffEntry::OnlyRight(rfield));
        }
    }
    diffs
}

// ─────────────────────────────────────────────────────────────────────────────
// TemplateReport — human-readable summary
// ─────────────────────────────────────────────────────────────────────────────

/// A rendered report for a single template application.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateReport {
    /// Template name.
    pub template_name: String,
    /// Buffer description or path.
    pub source: String,
    /// Flat list of fields.
    pub fields: Vec<TemplateField>,
    /// Total bytes covered by the template.
    pub total_size: usize,
    /// Number of top-level fields.
    pub field_count: usize,
}

impl TemplateReport {
    /// Build a report from a template application.
    #[must_use]
    pub fn build(template: &Template, parsed: &ParsedStruct, source: &str) -> Self {
        let fields = flatten_parsed(parsed);
        let total_size = fields.iter().map(|f| f.size).sum();
        let field_count = parsed.fields.len();
        Self {
            template_name: template.name.clone(),
            source: source.to_string(),
            fields,
            total_size,
            field_count,
        }
    }

    /// Render the report as a plain-text table.
    #[must_use]
    pub fn render_text(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!(
            "Template: {}  Source: {}  Fields: {}  Size: {} bytes\n",
            self.template_name, self.source, self.field_count, self.total_size
        ));
        out.push_str(&"-".repeat(80));
        out.push('\n');
        for f in &self.fields {
            out.push_str(&f.format_line());
            out.push('\n');
        }
        out
    }

    /// Serialise the report to JSON.
    ///
    /// # Errors
    /// Returns an error if JSON serialisation fails.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Deserialise a report from JSON.
    ///
    /// # Errors
    /// Returns an error if JSON deserialisation fails.
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// More built-in templates
// ─────────────────────────────────────────────────────────────────────────────

/// Returns a GIF89a file header template.
///
/// Layout: signature (6), logical screen descriptor (7).
#[must_use]
pub fn template_gif89a() -> Template {
    let mut t = Template::new("GIF89a", "GIF89a image header");
    t.add_field(bytes_field("Signature", 6).with_comment("'GIF89a'"));
    t.add_field(u16_field("LogicalScreenWidth"));
    t.add_field(u16_field("LogicalScreenHeight"));
    t.add_field(
        FieldDef::new("PackedField", TemplateType::Primitive(DataType::U8))
            .with_comment("GCT flag, color resolution, sort flag, GCT size"),
    );
    t.add_field(FieldDef::new(
        "BackgroundColorIndex",
        TemplateType::Primitive(DataType::U8),
    ));
    t.add_field(FieldDef::new(
        "PixelAspectRatio",
        TemplateType::Primitive(DataType::U8),
    ));
    t
}

/// Returns a BMP file header template (extended, public alias).
#[must_use]
pub fn template_bmp_header() -> Template {
    let mut t = Template::new("BMP", "BMP file and DIB header");
    // BITMAPFILEHEADER
    t.add_field(bytes_field("bfType", 2).with_comment("'BM'"));
    t.add_field(u32_field("bfSize").with_comment("file size in bytes"));
    t.add_field(u16_field("bfReserved1"));
    t.add_field(u16_field("bfReserved2"));
    t.add_field(u32_field("bfOffBits").with_comment("pixel data offset"));
    // BITMAPINFOHEADER
    t.add_field(u32_field("biSize").with_comment("40 for BITMAPINFOHEADER"));
    t.add_field(FieldDef::new(
        "biWidth",
        TemplateType::Primitive(DataType::I32Le),
    ));
    t.add_field(FieldDef::new(
        "biHeight",
        TemplateType::Primitive(DataType::I32Le),
    ));
    t.add_field(u16_field("biPlanes").with_comment("must be 1"));
    t.add_field(u16_field("biBitCount"));
    t.add_field(u32_field("biCompression"));
    t.add_field(u32_field("biSizeImage"));
    t.add_field(FieldDef::new(
        "biXPelsPerMeter",
        TemplateType::Primitive(DataType::I32Le),
    ));
    t.add_field(FieldDef::new(
        "biYPelsPerMeter",
        TemplateType::Primitive(DataType::I32Le),
    ));
    t.add_field(u32_field("biClrUsed"));
    t.add_field(u32_field("biClrImportant"));
    t
}

/// Returns a JPEG SOI + APP0 JFIF header template.
#[must_use]
pub fn template_jpeg_jfif() -> Template {
    let mut t = Template::new("JPEG_JFIF", "JPEG JFIF APP0 marker + header");
    t.add_field(bytes_field("SOI", 2).with_comment("FF D8"));
    t.add_field(bytes_field("APP0Marker", 2).with_comment("FF E0"));
    t.add_field(u16_field("APP0Length").with_comment("big-endian segment length"));
    t.add_field(bytes_field("Identifier", 5).with_comment("'JFIF\\0'"));
    t.add_field(FieldDef::new(
        "MajorVersion",
        TemplateType::Primitive(DataType::U8),
    ));
    t.add_field(FieldDef::new(
        "MinorVersion",
        TemplateType::Primitive(DataType::U8),
    ));
    t.add_field(
        FieldDef::new("Units", TemplateType::Primitive(DataType::U8))
            .with_comment("0=no units, 1=dots/inch, 2=dots/cm"),
    );
    t.add_field(u16_field("Xdensity"));
    t.add_field(u16_field("Ydensity"));
    t.add_field(FieldDef::new(
        "Xthumbnail",
        TemplateType::Primitive(DataType::U8),
    ));
    t.add_field(FieldDef::new(
        "Ythumbnail",
        TemplateType::Primitive(DataType::U8),
    ));
    t
}

/// Returns a ZIP local file header template.
#[must_use]
pub fn template_zip_local_file_header() -> Template {
    let mut t = Template::new("ZIP_LocalFileHeader", "ZIP local file entry header");
    t.add_field(u32_field("Signature").with_comment("0x04034B50"));
    t.add_field(u16_field("VersionNeededToExtract"));
    t.add_field(u16_field("GeneralPurposeBitFlag"));
    t.add_field(u16_field("CompressionMethod").with_comment("0=stored, 8=deflate"));
    t.add_field(u16_field("LastModFileTime"));
    t.add_field(u16_field("LastModFileDate"));
    t.add_field(u32_field("Crc32"));
    t.add_field(u32_field("CompressedSize"));
    t.add_field(u32_field("UncompressedSize"));
    t.add_field(u16_field("FileNameLength"));
    t.add_field(u16_field("ExtraFieldLength"));
    t
}

/// Returns a ZIP end-of-central-directory record template.
#[must_use]
pub fn template_zip_eocd() -> Template {
    let mut t = Template::new("ZIP_EOCD", "ZIP end-of-central-directory record");
    t.add_field(u32_field("Signature").with_comment("0x06054B50"));
    t.add_field(u16_field("DiskNumber"));
    t.add_field(u16_field("StartDisk"));
    t.add_field(u16_field("EntriesOnDisk"));
    t.add_field(u16_field("TotalEntries"));
    t.add_field(u32_field("CentralDirSize"));
    t.add_field(u32_field("CentralDirOffset"));
    t.add_field(u16_field("CommentLength"));
    t
}

/// Returns a COFF/PE file header template (IMAGE_FILE_HEADER).
#[must_use]
pub fn template_coff_file_header() -> Template {
    let mut t = Template::new("COFF_FileHeader", "PE/COFF IMAGE_FILE_HEADER");
    t.add_field(u16_field("Machine").with_comment("0x8664=x64, 0x14C=x86, 0xAA64=ARM64"));
    t.add_field(u16_field("NumberOfSections"));
    t.add_field(u32_field("TimeDateStamp"));
    t.add_field(u32_field("PointerToSymbolTable"));
    t.add_field(u32_field("NumberOfSymbols"));
    t.add_field(u16_field("SizeOfOptionalHeader"));
    t.add_field(u16_field("Characteristics"));
    t
}

/// Returns a PE32+ optional header template (64-bit).
#[must_use]
pub fn template_pe32plus_optional_header() -> Template {
    let mut t = Template::new("PE32Plus_OptionalHeader", "PE32+ (64-bit) Optional Header");
    t.add_field(u16_field("Magic").with_comment("0x20B for PE32+"));
    t.add_field(FieldDef::new(
        "MajorLinkerVersion",
        TemplateType::Primitive(DataType::U8),
    ));
    t.add_field(FieldDef::new(
        "MinorLinkerVersion",
        TemplateType::Primitive(DataType::U8),
    ));
    t.add_field(u32_field("SizeOfCode"));
    t.add_field(u32_field("SizeOfInitializedData"));
    t.add_field(u32_field("SizeOfUninitializedData"));
    t.add_field(u32_field("AddressOfEntryPoint"));
    t.add_field(u32_field("BaseOfCode"));
    t.add_field(u64_field("ImageBase"));
    t.add_field(u32_field("SectionAlignment"));
    t.add_field(u32_field("FileAlignment"));
    t.add_field(u16_field("MajorOperatingSystemVersion"));
    t.add_field(u16_field("MinorOperatingSystemVersion"));
    t.add_field(u16_field("MajorImageVersion"));
    t.add_field(u16_field("MinorImageVersion"));
    t.add_field(u16_field("MajorSubsystemVersion"));
    t.add_field(u16_field("MinorSubsystemVersion"));
    t.add_field(u32_field("Win32VersionValue"));
    t.add_field(u32_field("SizeOfImage"));
    t.add_field(u32_field("SizeOfHeaders"));
    t.add_field(u32_field("CheckSum"));
    t.add_field(u16_field("Subsystem"));
    t.add_field(u16_field("DllCharacteristics"));
    t.add_field(u64_field("SizeOfStackReserve"));
    t.add_field(u64_field("SizeOfStackCommit"));
    t.add_field(u64_field("SizeOfHeapReserve"));
    t.add_field(u64_field("SizeOfHeapCommit"));
    t.add_field(u32_field("LoaderFlags"));
    t.add_field(u32_field("NumberOfRvaAndSizes"));
    t
}

/// Returns an ELF64 section header entry template.
#[must_use]
pub fn template_elf64_shdr() -> Template {
    let mut t = Template::new("ELF64_SHDR", "ELF 64-bit Section Header Entry");
    t.add_field(u32_field("sh_name").with_comment("offset into .shstrtab"));
    t.add_field(u32_field("sh_type").with_comment("SHT_NULL=0, PROGBITS=1, SYMTAB=2..."));
    t.add_field(u64_field("sh_flags"));
    t.add_field(u64_field("sh_addr"));
    t.add_field(u64_field("sh_offset"));
    t.add_field(u64_field("sh_size"));
    t.add_field(u32_field("sh_link"));
    t.add_field(u32_field("sh_info"));
    t.add_field(u64_field("sh_addralign"));
    t.add_field(u64_field("sh_entsize"));
    t
}

/// Returns an ELF32 symbol table entry template.
#[must_use]
pub fn template_elf32_sym() -> Template {
    let mut t = Template::new("ELF32_Sym", "ELF 32-bit symbol table entry");
    t.add_field(u32_field("st_name"));
    t.add_field(u32_field("st_value"));
    t.add_field(u32_field("st_size"));
    t.add_field(FieldDef::new(
        "st_info",
        TemplateType::Primitive(DataType::U8),
    ));
    t.add_field(FieldDef::new(
        "st_other",
        TemplateType::Primitive(DataType::U8),
    ));
    t.add_field(u16_field("st_shndx"));
    t
}

/// Returns an ELF64 symbol table entry template.
#[must_use]
pub fn template_elf64_sym() -> Template {
    let mut t = Template::new("ELF64_Sym", "ELF 64-bit symbol table entry");
    t.add_field(u32_field("st_name"));
    t.add_field(FieldDef::new(
        "st_info",
        TemplateType::Primitive(DataType::U8),
    ));
    t.add_field(FieldDef::new(
        "st_other",
        TemplateType::Primitive(DataType::U8),
    ));
    t.add_field(u16_field("st_shndx"));
    t.add_field(u64_field("st_value"));
    t.add_field(u64_field("st_size"));
    t
}

/// Returns a Mach-O load command (generic) template.
#[must_use]
pub fn template_macho_load_command() -> Template {
    let mut t = Template::new("MachO_LoadCommand", "Generic Mach-O load command");
    t.add_field(u32_field("cmd").with_comment("LC_* constant"));
    t.add_field(u32_field("cmdsize").with_comment("size including data"));
    t
}

/// Returns a Mach-O LC_SEGMENT_64 template.
#[must_use]
pub fn template_macho_segment64() -> Template {
    let mut t = Template::new("MachO_Segment64", "Mach-O LC_SEGMENT_64 load command");
    t.add_field(u32_field("cmd").with_comment("0x19"));
    t.add_field(u32_field("cmdsize"));
    t.add_field(bytes_field("segname", 16).with_comment("segment name, null-padded"));
    t.add_field(u64_field("vmaddr"));
    t.add_field(u64_field("vmsize"));
    t.add_field(u64_field("fileoff"));
    t.add_field(u64_field("filesize"));
    t.add_field(u32_field("maxprot").with_comment("maximum VM protection"));
    t.add_field(u32_field("initprot").with_comment("initial VM protection"));
    t.add_field(u32_field("nsects").with_comment("number of sections in segment"));
    t.add_field(u32_field("flags"));
    t
}

/// Returns an ELF relocation entry (REL, 64-bit) template.
#[must_use]
pub fn template_elf64_rel() -> Template {
    let mut t = Template::new("ELF64_Rel", "ELF 64-bit relocation entry (Rel)");
    t.add_field(u64_field("r_offset"));
    t.add_field(u64_field("r_info").with_comment("sym<<32 | type"));
    t
}

/// Returns an ELF relocation entry (RELA, 64-bit) template.
#[must_use]
pub fn template_elf64_rela() -> Template {
    let mut t = Template::new("ELF64_Rela", "ELF 64-bit relocation entry (Rela)");
    t.add_field(u64_field("r_offset"));
    t.add_field(u64_field("r_info"));
    t.add_field(FieldDef::new(
        "r_addend",
        TemplateType::Primitive(DataType::I64Le),
    ));
    t
}

/// Returns a COFF relocation entry template.
#[must_use]
pub fn template_coff_reloc() -> Template {
    let mut t = Template::new("COFF_Reloc", "COFF relocation entry");
    t.add_field(u32_field("VirtualAddress"));
    t.add_field(u32_field("SymbolTableIndex"));
    t.add_field(u16_field("Type"));
    t
}

/// Returns a PE import directory entry template (IMAGE_IMPORT_DESCRIPTOR).
#[must_use]
pub fn template_pe_import_descriptor() -> Template {
    let mut t = Template::new("PE_ImportDescriptor", "PE IMAGE_IMPORT_DESCRIPTOR");
    t.add_field(u32_field("OriginalFirstThunk").with_comment("RVA to INT"));
    t.add_field(u32_field("TimeDateStamp"));
    t.add_field(u32_field("ForwarderChain").with_comment("-1 if no forwarders"));
    t.add_field(u32_field("Name").with_comment("RVA to DLL name string"));
    t.add_field(u32_field("FirstThunk").with_comment("RVA to IAT"));
    t
}

/// Returns a PE export directory template (IMAGE_EXPORT_DIRECTORY).
#[must_use]
pub fn template_pe_export_directory() -> Template {
    let mut t = Template::new("PE_ExportDirectory", "PE IMAGE_EXPORT_DIRECTORY");
    t.add_field(u32_field("Characteristics"));
    t.add_field(u32_field("TimeDateStamp"));
    t.add_field(u16_field("MajorVersion"));
    t.add_field(u16_field("MinorVersion"));
    t.add_field(u32_field("Name").with_comment("RVA to module name"));
    t.add_field(u32_field("Base").with_comment("ordinal base"));
    t.add_field(u32_field("NumberOfFunctions"));
    t.add_field(u32_field("NumberOfNames"));
    t.add_field(u32_field("AddressOfFunctions"));
    t.add_field(u32_field("AddressOfNames"));
    t.add_field(u32_field("AddressOfNameOrdinals"));
    t
}

/// Returns a PE TLS directory template (IMAGE_TLS_DIRECTORY64).
#[must_use]
pub fn template_pe_tls_directory64() -> Template {
    let mut t = Template::new("PE_TlsDirectory64", "PE IMAGE_TLS_DIRECTORY64");
    t.add_field(u64_field("StartAddressOfRawData"));
    t.add_field(u64_field("EndAddressOfRawData"));
    t.add_field(u64_field("AddressOfIndex"));
    t.add_field(u64_field("AddressOfCallBacks"));
    t.add_field(u32_field("SizeOfZeroFill"));
    t.add_field(u32_field("Characteristics"));
    t
}

/// Returns a PE debug directory entry template (IMAGE_DEBUG_DIRECTORY).
#[must_use]
pub fn template_pe_debug_directory() -> Template {
    let mut t = Template::new("PE_DebugDirectory", "PE IMAGE_DEBUG_DIRECTORY");
    t.add_field(u32_field("Characteristics"));
    t.add_field(u32_field("TimeDateStamp"));
    t.add_field(u16_field("MajorVersion"));
    t.add_field(u16_field("MinorVersion"));
    t.add_field(u32_field("Type").with_comment("2=CodeView, 3=COFF, 4=FPO, 9=VC++"));
    t.add_field(u32_field("SizeOfData"));
    t.add_field(u32_field("AddressOfRawData").with_comment("RVA"));
    t.add_field(u32_field("PointerToRawData").with_comment("file offset"));
    t
}

// ─────────────────────────────────────────────────────────────────────────────
// TemplateSelector — choose a template by inspecting buffer magic bytes
// ─────────────────────────────────────────────────────────────────────────────

/// Selects the best matching built-in template for a buffer based on its magic
/// bytes.
#[must_use]
pub fn auto_select_template(data: &[u8]) -> Option<Template> {
    if data.len() < 4 {
        return None;
    }
    let magic4 = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    // ELF
    if data.starts_with(b"\x7fELF") {
        return if data.len() >= 5 && data[4] == 2 {
            Some(template_elf64_ehdr())
        } else {
            Some(template_elf32_ehdr())
        };
    }
    // PE/MZ
    if data.starts_with(b"MZ") {
        return Some(template_mz());
    }
    // PNG
    if data.starts_with(b"\x89PNG") {
        return Some(template_png());
    }
    // GIF
    if data.starts_with(b"GIF89") {
        return Some(template_gif89a());
    }
    // BMP
    if data.starts_with(b"BM") {
        return Some(template_bmp_header());
    }
    // JPEG
    if data.starts_with(b"\xff\xd8\xff") {
        return Some(template_jpeg_jfif());
    }
    // ZIP
    if magic4 == 0x04034B50 {
        return Some(template_zip_local_file_header());
    }
    // WAV
    if data.starts_with(b"RIFF") && data.len() >= 12 && &data[8..12] == b"WAVE" {
        return Some(template_wav());
    }
    // MP4 / ISO base media — ftyp box
    if data.len() >= 8 && &data[4..8] == b"ftyp" {
        return Some(template_mp4_box());
    }
    None
}

/// Returns an ELF32 executable header template.
#[must_use]
pub fn template_elf32_ehdr() -> Template {
    let mut t = Template::new("ELF32_Ehdr", "ELF 32-bit executable header");
    t.add_field(bytes_field("e_ident", 16).with_comment("magic + class + data + version + OS/ABI"));
    t.add_field(u16_field("e_type").with_comment("ET_EXEC=2, ET_DYN=3"));
    t.add_field(u16_field("e_machine").with_comment("3=x86, 40=ARM"));
    t.add_field(u32_field("e_version").with_comment("must be 1"));
    t.add_field(u32_field("e_entry"));
    t.add_field(u32_field("e_phoff").with_comment("program header offset"));
    t.add_field(u32_field("e_shoff").with_comment("section header offset"));
    t.add_field(u32_field("e_flags"));
    t.add_field(u16_field("e_ehsize").with_comment("52 bytes"));
    t.add_field(u16_field("e_phentsize"));
    t.add_field(u16_field("e_phnum"));
    t.add_field(u16_field("e_shentsize"));
    t.add_field(u16_field("e_shnum"));
    t.add_field(u16_field("e_shstrndx"));
    t
}

/// Returns an ELF64 executable header template.
#[must_use]
pub fn template_elf64_ehdr() -> Template {
    let mut t = Template::new("ELF64_Ehdr", "ELF 64-bit executable header");
    t.add_field(bytes_field("e_ident", 16).with_comment("magic + class + data + version + OS/ABI"));
    t.add_field(u16_field("e_type").with_comment("ET_EXEC=2, ET_DYN=3, ET_CORE=4"));
    t.add_field(u16_field("e_machine").with_comment("62=x86-64, 183=AArch64"));
    t.add_field(u32_field("e_version"));
    t.add_field(u64_field("e_entry"));
    t.add_field(u64_field("e_phoff"));
    t.add_field(u64_field("e_shoff"));
    t.add_field(u32_field("e_flags"));
    t.add_field(u16_field("e_ehsize").with_comment("64 bytes"));
    t.add_field(u16_field("e_phentsize"));
    t.add_field(u16_field("e_phnum"));
    t.add_field(u16_field("e_shentsize"));
    t.add_field(u16_field("e_shnum"));
    t.add_field(u16_field("e_shstrndx"));
    t
}

// ─────────────────────────────────────────────────────────────────────────────
// TemplateComposer — combine multiple templates into a composite parse
// ─────────────────────────────────────────────────────────────────────────────

/// Describes one layer in a composite template.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateLayer {
    /// The template to apply.
    pub template: Template,
    /// Byte offset at which to apply this template.
    pub offset: usize,
    /// Optional namespace prefix for field paths (e.g. `"ehdr"`).
    pub namespace: Option<String>,
}

impl TemplateLayer {
    /// Create a layer without a namespace.
    #[must_use]
    pub const fn new(template: Template, offset: usize) -> Self {
        Self {
            template,
            offset,
            namespace: None,
        }
    }

    /// Attach a namespace prefix.
    #[must_use]
    pub fn with_namespace(mut self, ns: impl Into<String>) -> Self {
        self.namespace = Some(ns.into());
        self
    }
}

/// A composite parse result: one [`ParsedStruct`] per layer, in order.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompositeResult {
    /// Per-layer results.
    pub layers: Vec<(Option<String>, ParsedStruct)>,
    /// Total distinct bytes covered.
    pub bytes_covered: usize,
}

impl CompositeResult {
    /// Flatten all layers into a single field list, prefixing with namespace.
    #[must_use]
    pub fn flatten_all(&self) -> Vec<TemplateField> {
        let mut out = Vec::new();
        for (ns, parsed) in &self.layers {
            let prefix = ns.as_deref().unwrap_or("");
            let fields = flatten_parsed(parsed);
            for mut f in fields {
                if !prefix.is_empty() {
                    f.path = format!("{prefix}.{}", f.path);
                }
                out.push(f);
            }
        }
        out
    }
}

/// Applies multiple templates at different offsets to a buffer, producing a
/// [`CompositeResult`].
pub struct TemplateComposer<'buf> {
    buffer: &'buf HexBuffer,
}

impl<'buf> TemplateComposer<'buf> {
    /// Create a new composer.
    #[must_use]
    pub const fn new(buffer: &'buf HexBuffer) -> Self {
        Self { buffer }
    }

    /// Apply all layers in order.
    ///
    /// # Errors
    /// Returns the first [`TemplateError`] encountered.
    pub fn apply_all(&self, layers: &[TemplateLayer]) -> Result<CompositeResult, TemplateError> {
        let mut results = Vec::new();
        let applier = TemplateApplier::new(self.buffer);
        for layer in layers {
            let parsed = applier.apply(&layer.template, layer.offset)?;
            results.push((layer.namespace.clone(), parsed));
        }
        let bytes_covered = results
            .iter()
            .flat_map(|(_, p)| p.fields.iter().map(|f| f.offset + f.size))
            .max()
            .unwrap_or(0);
        Ok(CompositeResult {
            layers: results,
            bytes_covered,
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// FieldSearch — search parsed output for fields by name or path
// ─────────────────────────────────────────────────────────────────────────────

/// Search a flat field list for an exact path match.
#[must_use]
pub fn find_field_by_path<'a>(
    fields: &'a [TemplateField],
    path: &str,
) -> Option<&'a TemplateField> {
    fields.iter().find(|f| f.path == path)
}

/// Search a flat field list for all fields whose name contains `needle`
/// (case-insensitive).
#[must_use]
pub fn find_fields_by_name<'a>(
    fields: &'a [TemplateField],
    needle: &str,
) -> Vec<&'a TemplateField> {
    let needle_lower = needle.to_lowercase();
    fields
        .iter()
        .filter(|f| f.name.to_lowercase().contains(&needle_lower))
        .collect()
}

/// Return all fields that overlap the byte range `[start, start+len)`.
#[must_use]
pub fn fields_in_range(fields: &[TemplateField], start: usize, len: usize) -> Vec<&TemplateField> {
    let end = start + len;
    fields
        .iter()
        .filter(|f| f.offset < end && f.offset + f.size > start)
        .collect()
}

// ─────────────────────────────────────────────────────────────────────────────
// TemplateAnnotation — attach user notes to parsed fields
// ─────────────────────────────────────────────────────────────────────────────

/// A user annotation on a specific field.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldAnnotation {
    /// Dotted path of the annotated field.
    pub path: String,
    /// User-provided note text.
    pub note: String,
    /// Optional colour tag (e.g. `"red"`, `"#FF0000"`).
    pub colour: Option<String>,
}

impl FieldAnnotation {
    /// Create a new annotation.
    #[must_use]
    pub fn new(path: impl Into<String>, note: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            note: note.into(),
            colour: None,
        }
    }

    /// Attach a colour tag.
    #[must_use]
    pub fn with_colour(mut self, colour: impl Into<String>) -> Self {
        self.colour = Some(colour.into());
        self
    }
}

/// A collection of annotations keyed by field path.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AnnotationSet {
    entries: Vec<FieldAnnotation>,
}

impl AnnotationSet {
    /// Create an empty set.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an annotation.
    pub fn add(&mut self, annotation: FieldAnnotation) {
        self.entries.push(annotation);
    }

    /// Look up the annotation for a field path (first match).
    #[must_use]
    pub fn get(&self, path: &str) -> Option<&FieldAnnotation> {
        self.entries.iter().find(|a| a.path == path)
    }

    /// All annotations.
    #[must_use]
    pub fn all(&self) -> &[FieldAnnotation] {
        &self.entries
    }

    /// Number of annotations.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the set is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Serialise to JSON.
    ///
    /// # Errors
    /// Returns an error if JSON serialisation fails.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(&self.entries)
    }

    /// Deserialise from JSON.
    ///
    /// # Errors
    /// Returns an error if JSON deserialisation fails.
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        let entries: Vec<FieldAnnotation> = serde_json::from_str(json)?;
        Ok(Self { entries })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TemplateHistory — record of recent template applications
// ─────────────────────────────────────────────────────────────────────────────

/// A single entry in the application history.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryEntry {
    /// Template name.
    pub template_name: String,
    /// Source description.
    pub source: String,
    /// Offset at which the template was applied.
    pub offset: usize,
    /// Number of fields parsed.
    pub fields_parsed: usize,
}

/// A bounded history of recent template applications.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateHistory {
    entries: Vec<HistoryEntry>,
    capacity: usize,
}

impl TemplateHistory {
    /// Create a new history with the given capacity.
    #[must_use]
    pub const fn new(capacity: usize) -> Self {
        Self {
            entries: Vec::new(),
            capacity,
        }
    }

    /// Record a new application.
    pub fn record(&mut self, entry: HistoryEntry) {
        if self.entries.len() >= self.capacity {
            self.entries.remove(0);
        }
        self.entries.push(entry);
    }

    /// All recorded entries (oldest first).
    #[must_use]
    pub fn entries(&self) -> &[HistoryEntry] {
        &self.entries
    }

    /// The most recent entry, if any.
    #[must_use]
    pub fn latest(&self) -> Option<&HistoryEntry> {
        self.entries.last()
    }

    /// Number of entries.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the history is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TemplateStats — statistics about a template definition
// ─────────────────────────────────────────────────────────────────────────────

/// Summary statistics about a template.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateStats {
    /// Total number of top-level field definitions.
    pub top_level_fields: usize,
    /// Total number of fields including nested struct members.
    pub total_fields: usize,
    /// Number of conditional fields.
    pub conditional_fields: usize,
    /// Number of repeated fields.
    pub repeated_fields: usize,
    /// Number of dynamic-array fields.
    pub dynarray_fields: usize,
    /// Minimum guaranteed byte size (fixed primitives only, no dynamics).
    pub min_fixed_size: usize,
}

/// Compute statistics for a template.
#[must_use]
pub fn template_stats(template: &Template) -> TemplateStats {
    let mut stats = TemplateStats {
        top_level_fields: template.fields.len(),
        total_fields: 0,
        conditional_fields: 0,
        repeated_fields: 0,
        dynarray_fields: 0,
        min_fixed_size: 0,
    };
    count_fields(&template.fields, &mut stats);
    stats
}

fn count_fields(fields: &[FieldDef], stats: &mut TemplateStats) {
    for f in fields {
        stats.total_fields += 1;
        if f.condition.is_some() {
            stats.conditional_fields += 1;
        }
        if f.repeat.is_some() {
            stats.repeated_fields += 1;
        }
        match &f.ty {
            TemplateType::DynArray { .. } => {
                stats.dynarray_fields += 1;
            }
            TemplateType::Struct(inner) => {
                count_fields(inner, stats);
            }
            TemplateType::Primitive(dt) => {
                if f.condition.is_none() && f.repeat.is_none() {
                    stats.min_fixed_size += dt.fixed_size().unwrap_or(0);
                }
            }
            _ => {}
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TemplateExporter — export to various text formats
// ─────────────────────────────────────────────────────────────────────────────

/// Export format options.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExportFormat {
    /// Plain text, one field per line.
    Text,
    /// CSV (path, offset, size, value, comment).
    Csv,
    /// Markdown table.
    Markdown,
    /// HTML table.
    Html,
}

/// Export a list of fields to a chosen format.
#[must_use]
pub fn export_fields(fields: &[TemplateField], format: ExportFormat) -> String {
    match format {
        ExportFormat::Text => fields
            .iter()
            .map(|f| f.format_line())
            .collect::<Vec<_>>()
            .join("\n"),
        ExportFormat::Csv => {
            let mut out = String::from("path,offset,size,value,comment\n");
            for f in fields {
                let comment = f.comment.as_deref().unwrap_or("");
                out.push_str(&format!(
                    "{},{},{},{},{}\n",
                    f.path, f.offset, f.size, f.display, comment
                ));
            }
            out
        }
        ExportFormat::Markdown => {
            let mut out = String::from("| Path | Offset | Size | Value | Comment |\n");
            out.push_str("|------|--------|------|-------|--------|\n");
            for f in fields {
                let comment = f.comment.as_deref().unwrap_or("");
                out.push_str(&format!(
                    "| `{}` | `{:#X}` | {} | `{}` | {} |\n",
                    f.path, f.offset, f.size, f.display, comment
                ));
            }
            out
        }
        ExportFormat::Html => {
            let mut out = String::from(
                "<table>\n<thead><tr><th>Path</th><th>Offset</th><th>Size</th>\
                 <th>Value</th><th>Comment</th></tr></thead>\n<tbody>\n",
            );
            for f in fields {
                let comment = f.comment.as_deref().unwrap_or("");
                out.push_str(&format!(
                    "<tr><td>{}</td><td>{:#X}</td><td>{}</td><td>{}</td><td>{}</td></tr>\n",
                    f.path, f.offset, f.size, f.display, comment
                ));
            }
            out.push_str("</tbody></table>\n");
            out
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Extended tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests_expanded2 {
    use super::*;

    fn buf(data: &[u8]) -> HexBuffer {
        HexBuffer::new(data.to_vec())
    }

    // ── TemplateField ─────────────────────────────────────────────────────────

    #[test]
    fn test_template_field_format_line_no_comment() {
        let f = TemplateField::new("magic", "magic", 0, 4, "0x7F454C46");
        let line = f.format_line();
        assert!(line.contains("magic"));
        assert!(line.contains("0x7F454C46"));
    }

    #[test]
    fn test_template_field_format_line_with_comment() {
        let f = TemplateField::new("sig", "sig", 0, 2, "0x5A4D").with_comment("'MZ'");
        let line = f.format_line();
        assert!(line.contains("// 'MZ'"));
    }

    #[test]
    fn test_template_field_depth_indent() {
        let f = TemplateField::new("x", "x", 0, 1, "0x00").with_depth(2);
        let line = f.format_line();
        assert!(line.starts_with("    ")); // 2×2 spaces
    }

    // ── flatten_parsed ────────────────────────────────────────────────────────

    #[test]
    fn test_flatten_parsed_simple() {
        let data = [0x01u8, 0x02];
        let b = buf(&data);
        let mut t = Template::new("T", "");
        t.add_field(FieldDef::new(
            "a",
            TemplateType::Primitive(rustre_hex::DataType::U8),
        ));
        t.add_field(FieldDef::new(
            "b",
            TemplateType::Primitive(rustre_hex::DataType::U8),
        ));
        let parsed = TemplateApplier::new(&b).apply(&t, 0).unwrap();
        let flat = flatten_parsed(&parsed);
        assert_eq!(flat.len(), 2);
        assert_eq!(flat[0].path, "a");
        assert_eq!(flat[1].path, "b");
    }

    #[test]
    fn test_flatten_parsed_nested() {
        let data = [0x01u8, 0x02, 0x03];
        let b = buf(&data);
        let inner = vec![
            FieldDef::new("x", TemplateType::Primitive(rustre_hex::DataType::U8)),
            FieldDef::new("y", TemplateType::Primitive(rustre_hex::DataType::U8)),
        ];
        let mut t = Template::new("T", "");
        t.add_field(FieldDef::new("pair", TemplateType::Struct(inner)));
        t.add_field(FieldDef::new(
            "z",
            TemplateType::Primitive(rustre_hex::DataType::U8),
        ));
        let parsed = TemplateApplier::new(&b).apply(&t, 0).unwrap();
        let flat = flatten_parsed(&parsed);
        // pair (struct) + pair.x + pair.y + z = 4
        assert!(flat.len() >= 3);
    }

    // ── diff_parsed ───────────────────────────────────────────────────────────

    #[test]
    fn test_diff_parsed_identical() {
        let data = [0x01u8, 0x02];
        let b = buf(&data);
        let mut t = Template::new("T", "");
        t.add_field(FieldDef::new(
            "a",
            TemplateType::Primitive(rustre_hex::DataType::U8),
        ));
        t.add_field(FieldDef::new(
            "b",
            TemplateType::Primitive(rustre_hex::DataType::U8),
        ));
        let p1 = TemplateApplier::new(&b).apply(&t, 0).unwrap();
        let p2 = TemplateApplier::new(&b).apply(&t, 0).unwrap();
        let diffs = diff_parsed(&p1, &p2);
        assert!(diffs.is_empty());
    }

    #[test]
    fn test_diff_parsed_value_change() {
        let data1 = [0x01u8, 0x02];
        let data2 = [0x01u8, 0xFF];
        let b1 = buf(&data1);
        let b2 = buf(&data2);
        let mut t = Template::new("T", "");
        t.add_field(FieldDef::new(
            "a",
            TemplateType::Primitive(rustre_hex::DataType::U8),
        ));
        t.add_field(FieldDef::new(
            "b",
            TemplateType::Primitive(rustre_hex::DataType::U8),
        ));
        let p1 = TemplateApplier::new(&b1).apply(&t, 0).unwrap();
        let p2 = TemplateApplier::new(&b2).apply(&t, 0).unwrap();
        let diffs = diff_parsed(&p1, &p2);
        assert!(!diffs.is_empty());
        assert!(diffs.iter().any(|d| d.path() == "b" && d.is_change()));
    }

    // ── TemplateReport ────────────────────────────────────────────────────────

    #[test]
    fn test_report_build_and_render() {
        // ELF64 header is 64 bytes; provide a zero-padded buffer
        let mut data = vec![0u8; 64];
        data[0] = 0x7F;
        data[1] = b'E';
        data[2] = b'L';
        data[3] = b'F';
        data[4] = 0x02; // 64-bit
        let b = buf(&data);
        let t = template_elf64_ehdr();
        let parsed = TemplateApplier::new(&b).apply(&t, 0).unwrap();
        let report = TemplateReport::build(&t, &parsed, "test.elf");
        let text = report.render_text();
        assert!(text.contains("ELF64_Ehdr"));
        assert!(text.contains("test.elf"));
    }

    #[test]
    fn test_report_json_roundtrip() {
        let data = [0x01u8, 0x02, 0x03, 0x04];
        let b = buf(&data);
        let mut t = Template::new("T", "");
        t.add_field(FieldDef::new(
            "a",
            TemplateType::Primitive(rustre_hex::DataType::U32Le),
        ));
        let parsed = TemplateApplier::new(&b).apply(&t, 0).unwrap();
        let report = TemplateReport::build(&t, &parsed, "buf");
        let json = report.to_json().unwrap();
        let report2 = TemplateReport::from_json(&json).unwrap();
        assert_eq!(report2.template_name, "T");
        assert_eq!(report2.field_count, 1);
    }

    // ── auto_select_template ──────────────────────────────────────────────────

    #[test]
    fn test_auto_select_elf64() {
        let data: Vec<u8> = {
            let mut v = vec![0x7f, b'E', b'L', b'F', 0x02];
            v.extend_from_slice(&[0u8; 64]);
            v
        };
        let tpl = auto_select_template(&data);
        assert!(tpl.is_some());
        assert_eq!(tpl.unwrap().name, "ELF64_Ehdr");
    }

    #[test]
    fn test_auto_select_elf32() {
        let data: Vec<u8> = {
            let mut v = vec![0x7f, b'E', b'L', b'F', 0x01];
            v.extend_from_slice(&[0u8; 64]);
            v
        };
        let tpl = auto_select_template(&data);
        assert!(tpl.is_some());
        assert_eq!(tpl.unwrap().name, "ELF32_Ehdr");
    }

    #[test]
    fn test_auto_select_mz() {
        let data = [b'M', b'Z', 0x90, 0x00];
        let tpl = auto_select_template(&data);
        assert!(tpl.is_some());
        assert_eq!(tpl.unwrap().name, "MZ");
    }

    #[test]
    fn test_auto_select_png() {
        let data = [0x89u8, b'P', b'N', b'G', b'\r', b'\n', 0x1A, b'\n'];
        let tpl = auto_select_template(&data);
        assert!(tpl.is_some());
        assert_eq!(tpl.unwrap().name, "PNG");
    }

    #[test]
    fn test_auto_select_none() {
        let data = [0xAA, 0xBB, 0xCC, 0xDD];
        let tpl = auto_select_template(&data);
        assert!(tpl.is_none());
    }

    #[test]
    fn test_auto_select_short_data() {
        let data = [0x7f];
        let tpl = auto_select_template(&data);
        assert!(tpl.is_none());
    }

    // ── Extended template field counts ────────────────────────────────────────

    #[test]
    fn test_gif89a_template_fields() {
        let t = template_gif89a();
        assert_eq!(t.fields.len(), 6);
    }

    #[test]
    fn test_bmp_template_fields() {
        let t = template_bmp_header();
        assert_eq!(t.fields.len(), 16);
    }

    #[test]
    fn test_jpeg_jfif_template_fields() {
        let t = template_jpeg_jfif();
        assert_eq!(t.fields.len(), 11);
    }

    #[test]
    fn test_zip_local_header_fields() {
        let t = template_zip_local_file_header();
        assert_eq!(t.fields.len(), 11);
    }

    #[test]
    fn test_zip_eocd_fields() {
        let t = template_zip_eocd();
        assert_eq!(t.fields.len(), 8);
    }

    #[test]
    fn test_coff_file_header_fields() {
        let t = template_coff_file_header();
        assert_eq!(t.fields.len(), 7);
    }

    #[test]
    fn test_pe32plus_optional_header_fields() {
        let t = template_pe32plus_optional_header();
        assert!(t.fields.len() >= 28);
    }

    #[test]
    fn test_elf64_shdr_fields() {
        let t = template_elf64_shdr();
        assert_eq!(t.fields.len(), 10);
    }

    #[test]
    fn test_elf32_sym_fields() {
        let t = template_elf32_sym();
        assert_eq!(t.fields.len(), 6);
    }

    #[test]
    fn test_elf64_sym_fields() {
        let t = template_elf64_sym();
        assert_eq!(t.fields.len(), 6);
    }

    #[test]
    fn test_macho_load_command_fields() {
        let t = template_macho_load_command();
        assert_eq!(t.fields.len(), 2);
    }

    #[test]
    fn test_macho_segment64_fields() {
        let t = template_macho_segment64();
        assert_eq!(t.fields.len(), 11);
    }

    #[test]
    fn test_elf64_rel_fields() {
        let t = template_elf64_rel();
        assert_eq!(t.fields.len(), 2);
    }

    #[test]
    fn test_elf64_rela_fields() {
        let t = template_elf64_rela();
        assert_eq!(t.fields.len(), 3);
    }

    #[test]
    fn test_coff_reloc_fields() {
        let t = template_coff_reloc();
        assert_eq!(t.fields.len(), 3);
    }

    #[test]
    fn test_pe_import_descriptor_fields() {
        let t = template_pe_import_descriptor();
        assert_eq!(t.fields.len(), 5);
    }

    #[test]
    fn test_pe_export_directory_fields() {
        let t = template_pe_export_directory();
        assert_eq!(t.fields.len(), 11);
    }

    #[test]
    fn test_pe_tls_directory_fields() {
        let t = template_pe_tls_directory64();
        assert_eq!(t.fields.len(), 6);
    }

    #[test]
    fn test_pe_debug_directory_fields() {
        let t = template_pe_debug_directory();
        assert_eq!(t.fields.len(), 8);
    }

    // ── TemplateComposer ──────────────────────────────────────────────────────

    #[test]
    fn test_composer_two_layers() {
        let data = [0x01u8, 0x02, 0x03, 0x04];
        let b = buf(&data);
        let mut t1 = Template::new("T1", "");
        t1.add_field(FieldDef::new(
            "a",
            TemplateType::Primitive(rustre_hex::DataType::U8),
        ));
        let mut t2 = Template::new("T2", "");
        t2.add_field(FieldDef::new(
            "b",
            TemplateType::Primitive(rustre_hex::DataType::U8),
        ));
        let layers = vec![
            TemplateLayer::new(t1, 0).with_namespace("l1"),
            TemplateLayer::new(t2, 1).with_namespace("l2"),
        ];
        let composer = TemplateComposer::new(&b);
        let result = composer.apply_all(&layers).unwrap();
        assert_eq!(result.layers.len(), 2);
        let flat = result.flatten_all();
        assert!(flat.iter().any(|f| f.path.starts_with("l1.")));
        assert!(flat.iter().any(|f| f.path.starts_with("l2.")));
    }

    // ── find_field_by_path / find_fields_by_name ──────────────────────────────

    #[test]
    fn test_find_field_by_path_found() {
        let fields = vec![
            TemplateField::new("magic", "magic", 0, 4, "0x7F454C46"),
            TemplateField::new("type", "type", 4, 2, "0x0002"),
        ];
        let f = find_field_by_path(&fields, "magic");
        assert!(f.is_some());
        assert_eq!(f.unwrap().size, 4);
    }

    #[test]
    fn test_find_field_by_path_not_found() {
        let fields: Vec<TemplateField> = Vec::new();
        assert!(find_field_by_path(&fields, "nonexistent").is_none());
    }

    #[test]
    fn test_find_fields_by_name_partial() {
        let fields = vec![
            TemplateField::new("BitmapWidth", "BitmapWidth", 0, 4, "640"),
            TemplateField::new("BitmapHeight", "BitmapHeight", 4, 4, "480"),
            TemplateField::new("Type", "Type", 8, 2, "0x01"),
        ];
        let found = find_fields_by_name(&fields, "bitmap");
        assert_eq!(found.len(), 2);
    }

    #[test]
    fn test_fields_in_range() {
        let fields = vec![
            TemplateField::new("a", "a", 0, 4, "val"),
            TemplateField::new("b", "b", 4, 4, "val"),
            TemplateField::new("c", "c", 8, 4, "val"),
        ];
        let hits = fields_in_range(&fields, 3, 4);
        // fields 'a' (0..4) and 'b' (4..8) both overlap [3,7)
        assert!(!hits.is_empty());
    }

    // ── AnnotationSet ─────────────────────────────────────────────────────────

    #[test]
    fn test_annotation_add_and_get() {
        let mut set = AnnotationSet::new();
        set.add(FieldAnnotation::new("magic", "ELF magic bytes"));
        assert_eq!(set.len(), 1);
        let a = set.get("magic").unwrap();
        assert_eq!(a.note, "ELF magic bytes");
    }

    #[test]
    fn test_annotation_colour() {
        let a = FieldAnnotation::new("entry", "entry point").with_colour("green");
        assert_eq!(a.colour.as_deref(), Some("green"));
    }

    #[test]
    fn test_annotation_json_roundtrip() {
        let mut set = AnnotationSet::new();
        set.add(FieldAnnotation::new("a", "note a").with_colour("red"));
        set.add(FieldAnnotation::new("b", "note b"));
        let json = set.to_json().unwrap();
        let set2 = AnnotationSet::from_json(&json).unwrap();
        assert_eq!(set2.len(), 2);
    }

    // ── TemplateHistory ───────────────────────────────────────────────────────

    #[test]
    fn test_history_record_and_retrieve() {
        let mut h = TemplateHistory::new(10);
        h.record(HistoryEntry {
            template_name: "ELF64_Ehdr".into(),
            source: "test.elf".into(),
            offset: 0,
            fields_parsed: 14,
        });
        assert_eq!(h.len(), 1);
        assert_eq!(h.latest().unwrap().template_name, "ELF64_Ehdr");
    }

    #[test]
    fn test_history_capacity_eviction() {
        let mut h = TemplateHistory::new(3);
        for i in 0..5u32 {
            h.record(HistoryEntry {
                template_name: format!("T{i}"),
                source: "x".into(),
                offset: 0,
                fields_parsed: 1,
            });
        }
        assert_eq!(h.len(), 3);
        assert_eq!(h.latest().unwrap().template_name, "T4");
    }

    // ── TemplateStats ─────────────────────────────────────────────────────────

    #[test]
    fn test_template_stats_all_primitives() {
        let t = template_elf32_sym();
        let stats = template_stats(&t);
        assert_eq!(stats.top_level_fields, 6);
        assert_eq!(stats.total_fields, 6);
        assert_eq!(stats.conditional_fields, 0);
        assert_eq!(stats.repeated_fields, 0);
    }

    #[test]
    fn test_template_stats_min_fixed_size_mz() {
        let t = template_mz();
        let stats = template_stats(&t);
        // MZ has several u16 and u32 fields
        assert!(stats.min_fixed_size >= 16);
    }

    // ── export_fields ─────────────────────────────────────────────────────────

    #[test]
    fn test_export_fields_text() {
        let fields = vec![TemplateField::new("magic", "magic", 0, 4, "0x7F454C46")];
        let out = export_fields(&fields, ExportFormat::Text);
        assert!(out.contains("magic"));
        assert!(out.contains("0x7F454C46"));
    }

    #[test]
    fn test_export_fields_csv() {
        let fields = vec![TemplateField::new("a", "a", 0, 1, "0x01")];
        let out = export_fields(&fields, ExportFormat::Csv);
        assert!(out.contains("path,offset,size,value,comment"));
        assert!(out.contains("a,0,1,0x01,"));
    }

    #[test]
    fn test_export_fields_markdown() {
        let fields = vec![TemplateField::new("type", "type", 4, 2, "0x0002")];
        let out = export_fields(&fields, ExportFormat::Markdown);
        assert!(out.contains("| Path |"));
        assert!(out.contains("`type`"));
    }

    #[test]
    fn test_export_fields_html() {
        let fields = vec![TemplateField::new("x", "x", 0, 1, "0x00")];
        let out = export_fields(&fields, ExportFormat::Html);
        assert!(out.contains("<table>"));
        assert!(out.contains("<td>x</td>"));
    }

    // ── elf32/elf64 ehdr templates ────────────────────────────────────────────

    #[test]
    fn test_elf32_ehdr_field_count() {
        let t = template_elf32_ehdr();
        assert_eq!(t.fields.len(), 14);
    }

    #[test]
    fn test_elf64_ehdr_field_count() {
        let t = template_elf64_ehdr();
        assert_eq!(t.fields.len(), 14);
    }

    #[test]
    fn test_elf64_ehdr_first_field() {
        let t = template_elf64_ehdr();
        assert_eq!(t.fields[0].name, "e_ident");
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Additional format templates
// ─────────────────────────────────────────────────────────────────────────────

/// Returns a PE Rich header marker template (undocumented, before PE header).
#[must_use]
pub fn template_pe_rich_header() -> Template {
    let mut t = Template::new("PE_RichHeader", "PE Rich header marker (undocumented)");
    t.add_field(u32_field("DanSMagic").with_comment("0x536E6144 ('DanS' XOR'd)"));
    t.add_field(u32_field("XorKey1"));
    t.add_field(u32_field("XorKey2"));
    t.add_field(u32_field("XorKey3"));
    t
}

/// Returns a DWARF CIE (Common Information Entry) header template.
#[must_use]
pub fn template_dwarf_cie() -> Template {
    let mut t = Template::new("DWARF_CIE", "DWARF .debug_frame CIE header");
    t.add_field(u32_field("length").with_comment("0xFFFFFFFF = 64-bit DWARF"));
    t.add_field(u32_field("CIE_id").with_comment("0xFFFFFFFF"));
    t.add_field(
        FieldDef::new("version", TemplateType::Primitive(DataType::U8)).with_comment("1 or 3"),
    );
    t
}

/// Returns a DWARF FDE (Frame Description Entry) header template.
#[must_use]
pub fn template_dwarf_fde() -> Template {
    let mut t = Template::new("DWARF_FDE", "DWARF .debug_frame FDE header");
    t.add_field(u32_field("length"));
    t.add_field(u32_field("CIE_pointer").with_comment("offset to associated CIE"));
    t.add_field(u64_field("initial_location").with_comment("start address covered"));
    t.add_field(u64_field("address_range").with_comment("length of covered range"));
    t
}

/// Returns an ELF dynamic section entry template (Elf64_Dyn).
#[must_use]
pub fn template_elf64_dyn() -> Template {
    let mut t = Template::new("ELF64_Dyn", "ELF 64-bit dynamic section entry");
    t.add_field(
        FieldDef::new("d_tag", TemplateType::Primitive(DataType::I64Le))
            .with_comment("DT_NULL=0, DT_NEEDED=1, DT_SONAME=14..."),
    );
    t.add_field(u64_field("d_val_or_ptr").with_comment("d_val or d_ptr union"));
    t
}

/// Returns an ELF note header template (Elf_Nhdr).
#[must_use]
pub fn template_elf_nhdr() -> Template {
    let mut t = Template::new("ELF_Nhdr", "ELF note header (Elf_Nhdr)");
    t.add_field(u32_field("namesz").with_comment("length of note name including null"));
    t.add_field(u32_field("descsz").with_comment("length of note descriptor"));
    t.add_field(u32_field("type_").with_comment("note type (depends on owner)"));
    t
}

/// Returns a PE .NET metadata header (STORAGE_SIGNATURE) template.
#[must_use]
pub fn template_dotnet_metadata_sig() -> Template {
    let mut t = Template::new("DotNet_MetadataSig", ".NET metadata storage signature");
    t.add_field(u32_field("Signature").with_comment("0x424A5342 'BSJB'"));
    t.add_field(u16_field("MajorVersion").with_comment("1"));
    t.add_field(u16_field("MinorVersion").with_comment("1"));
    t.add_field(u32_field("Reserved").with_comment("0"));
    t.add_field(u32_field("VersionLength"));
    t
}

/// Returns a DEX file header template (Android Dalvik).
#[must_use]
pub fn template_dex_header() -> Template {
    let mut t = Template::new("DEX_Header", "Android DEX file header");
    t.add_field(bytes_field("magic", 8).with_comment("'dex\\n035\\0'"));
    t.add_field(u32_field("checksum").with_comment("Adler-32 of rest of file"));
    t.add_field(bytes_field("sha1", 20).with_comment("SHA-1 of rest of file"));
    t.add_field(u32_field("file_size"));
    t.add_field(u32_field("header_size").with_comment("0x70 = 112 bytes"));
    t.add_field(u32_field("endian_tag").with_comment("0x12345678 = LE"));
    t.add_field(u32_field("link_size"));
    t.add_field(u32_field("link_off"));
    t.add_field(u32_field("map_off"));
    t.add_field(u32_field("string_ids_size"));
    t.add_field(u32_field("string_ids_off"));
    t.add_field(u32_field("type_ids_size"));
    t.add_field(u32_field("type_ids_off"));
    t.add_field(u32_field("proto_ids_size"));
    t.add_field(u32_field("proto_ids_off"));
    t.add_field(u32_field("field_ids_size"));
    t.add_field(u32_field("field_ids_off"));
    t.add_field(u32_field("method_ids_size"));
    t.add_field(u32_field("method_ids_off"));
    t.add_field(u32_field("class_defs_size"));
    t.add_field(u32_field("class_defs_off"));
    t.add_field(u32_field("data_size"));
    t.add_field(u32_field("data_off"));
    t
}

/// Returns an OAT (Android ART) magic template.
#[must_use]
pub fn template_oat_magic() -> Template {
    let mut t = Template::new("OAT_Magic", "Android OAT file magic");
    t.add_field(bytes_field("magic", 4).with_comment("'oat\\n'"));
    t.add_field(bytes_field("version", 4).with_comment("e.g. '188\\0'"));
    t
}

/// Returns an AIFF file header template.
#[must_use]
pub fn template_aiff_header() -> Template {
    let mut t = Template::new("AIFF_Header", "AIFF file header chunk");
    t.add_field(bytes_field("ckID", 4).with_comment("'FORM'"));
    t.add_field(u32_field("ckSize").with_comment("big-endian"));
    t.add_field(bytes_field("formType", 4).with_comment("'AIFF' or 'AIFC'"));
    t
}

// ─────────────────────────────────────────────────────────────────────────────
// Additional tests for new templates
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests_expanded3 {
    use super::*;

    #[test]
    fn test_pe_rich_header_fields() {
        let t = template_pe_rich_header();
        assert_eq!(t.fields.len(), 4);
        assert_eq!(t.fields[0].name, "DanSMagic");
    }

    #[test]
    fn test_dwarf_cie_fields() {
        let t = template_dwarf_cie();
        assert_eq!(t.fields.len(), 3);
    }

    #[test]
    fn test_dwarf_fde_fields() {
        let t = template_dwarf_fde();
        assert_eq!(t.fields.len(), 4);
    }

    #[test]
    fn test_elf64_dyn_fields() {
        let t = template_elf64_dyn();
        assert_eq!(t.fields.len(), 2);
    }

    #[test]
    fn test_elf_nhdr_fields() {
        let t = template_elf_nhdr();
        assert_eq!(t.fields.len(), 3);
        assert_eq!(t.fields[0].name, "namesz");
    }

    #[test]
    fn test_dotnet_metadata_sig_fields() {
        let t = template_dotnet_metadata_sig();
        assert_eq!(t.fields.len(), 5);
        assert_eq!(t.fields[0].name, "Signature");
    }

    #[test]
    fn test_dex_header_fields() {
        let t = template_dex_header();
        assert_eq!(t.fields.len(), 23);
        assert_eq!(t.fields[0].name, "magic");
    }

    #[test]
    fn test_oat_magic_fields() {
        let t = template_oat_magic();
        assert_eq!(t.fields.len(), 2);
    }

    #[test]
    fn test_aiff_header_fields() {
        let t = template_aiff_header();
        assert_eq!(t.fields.len(), 3);
    }

    #[test]
    fn test_elf64_shdr_name_is_sh_name() {
        let t = template_elf64_shdr();
        assert_eq!(t.fields[0].name, "sh_name");
    }

    #[test]
    fn test_template_stats_elf64_dyn() {
        let t = template_elf64_dyn();
        let stats = template_stats(&t);
        assert_eq!(stats.total_fields, 2);
        assert_eq!(stats.conditional_fields, 0);
        assert!(stats.min_fixed_size >= 8);
    }

    #[test]
    fn test_export_fields_empty_text() {
        let out = export_fields(&[], ExportFormat::Text);
        assert!(out.is_empty());
    }

    #[test]
    fn test_export_fields_empty_csv() {
        let out = export_fields(&[], ExportFormat::Csv);
        assert!(out.contains("path,offset,size,value,comment"));
    }

    #[test]
    fn test_export_fields_empty_markdown() {
        let out = export_fields(&[], ExportFormat::Markdown);
        assert!(out.contains("| Path |"));
    }

    #[test]
    fn test_export_fields_empty_html() {
        let out = export_fields(&[], ExportFormat::Html);
        assert!(out.contains("<table>"));
        assert!(out.contains("</table>"));
    }

    #[test]
    fn test_find_fields_by_name_empty() {
        let fields: Vec<TemplateField> = Vec::new();
        assert!(find_fields_by_name(&fields, "magic").is_empty());
    }

    #[test]
    fn test_fields_in_range_no_overlap() {
        let fields = vec![TemplateField::new("a", "a", 0, 4, "x")];
        let hits = fields_in_range(&fields, 10, 4);
        assert!(hits.is_empty());
    }

    #[test]
    fn test_annotation_empty() {
        let set = AnnotationSet::new();
        assert!(set.is_empty());
        assert!(set.get("anything").is_none());
    }

    #[test]
    fn test_history_empty() {
        let h = TemplateHistory::new(5);
        assert!(h.is_empty());
        assert!(h.latest().is_none());
    }

    #[test]
    fn test_template_stats_bmp() {
        let t = template_bmp_header();
        let stats = template_stats(&t);
        assert_eq!(stats.top_level_fields, 16);
        assert!(stats.min_fixed_size >= 40);
    }

    #[test]
    fn test_dex_header_field_names() {
        let t = template_dex_header();
        let names: Vec<&str> = t.fields.iter().map(|f| f.name.as_str()).collect();
        assert!(names.contains(&"checksum"));
        assert!(names.contains(&"file_size"));
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// More format templates
// ─────────────────────────────────────────────────────────────────────────────

/// ELF 32-bit symbol table entry (Elf32_Sym).
#[must_use]
pub fn template_elf32_sym2() -> Template {
    let mut t = Template::new("ELF32_Sym2", "ELF 32-bit symbol (Elf32_Sym)");
    t.add_field(u32_field("st_name"));
    t.add_field(u32_field("st_value"));
    t.add_field(u32_field("st_size"));
    t.add_field(FieldDef::new(
        "st_info",
        TemplateType::Primitive(DataType::U8),
    ));
    t.add_field(FieldDef::new(
        "st_other",
        TemplateType::Primitive(DataType::U8),
    ));
    t.add_field(u16_field("st_shndx"));
    t
}

/// ELF 64-bit symbol table entry (Elf64_Sym).
#[must_use]
pub fn template_elf64_sym_v2() -> Template {
    let mut t = Template::new("ELF64_Sym_v2", "ELF 64-bit symbol (Elf64_Sym)");
    t.add_field(u32_field("st_name"));
    t.add_field(FieldDef::new(
        "st_info",
        TemplateType::Primitive(DataType::U8),
    ));
    t.add_field(FieldDef::new(
        "st_other",
        TemplateType::Primitive(DataType::U8),
    ));
    t.add_field(u16_field("st_shndx"));
    t.add_field(u64_field("st_value"));
    t.add_field(u64_field("st_size"));
    t
}

/// ELF 64-bit relocation with addend (Elf64_Rela).
#[must_use]
pub fn template_elf64_rela_v2() -> Template {
    let mut t = Template::new("ELF64_Rela_v2", "ELF 64-bit relocation with addend");
    t.add_field(u64_field("r_offset").with_comment("location to apply reloc"));
    t.add_field(u64_field("r_info").with_comment("symbol index and type"));
    t.add_field(
        FieldDef::new("r_addend", TemplateType::Primitive(DataType::I64Le))
            .with_comment("addend value"),
    );
    t
}

/// COFF string table header.
#[must_use]
pub fn template_coff_string_table() -> Template {
    let mut t = Template::new("COFF_StringTable", "COFF string table header");
    t.add_field(u32_field("TableSize").with_comment("total size including this field"));
    t
}

/// COFF relocation entry.
#[must_use]
pub fn template_coff_reloc_v2() -> Template {
    let mut t = Template::new("COFF_Reloc_v2", "COFF relocation entry");
    t.add_field(u32_field("VirtualAddress").with_comment("target offset"));
    t.add_field(u32_field("SymbolTableIndex"));
    t.add_field(u16_field("Type").with_comment("machine-specific reloc type"));
    t
}

/// WebAssembly (WASM) section header.
#[must_use]
pub fn template_wasm_section() -> Template {
    let mut t = Template::new("WASM_Section", "WebAssembly binary section header");
    t.add_field(
        FieldDef::new("id", TemplateType::Primitive(DataType::U8))
            .with_comment("0=custom,1=type,2=import,3=func..."),
    );
    t.add_field(u32_field("size").with_comment("LEB128 encoded in binary, stored as u32 here"));
    t
}

/// Mach-O fat binary header.
#[must_use]
pub fn template_macho_fat_header() -> Template {
    let mut t = Template::new("MachO_FatHeader", "Mach-O fat binary header");
    t.add_field(u32_field("magic").with_comment("0xCAFEBABE (big-endian)"));
    t.add_field(u32_field("nfat_arch").with_comment("number of fat_arch entries"));
    t
}

/// Mach-O fat_arch entry.
#[must_use]
pub fn template_macho_fat_arch() -> Template {
    let mut t = Template::new("MachO_FatArch", "Mach-O fat_arch entry");
    t.add_field(u32_field("cputype").with_comment("CPU_TYPE_*"));
    t.add_field(u32_field("cpusubtype"));
    t.add_field(u32_field("offset").with_comment("file offset to arch binary"));
    t.add_field(u32_field("size").with_comment("size of the arch binary"));
    t.add_field(u32_field("align").with_comment("log2 alignment"));
    t
}

/// Java class file header (first 10 bytes).
#[must_use]
pub fn template_java_class_header() -> Template {
    let mut t = Template::new("Java_ClassHeader", "Java .class file header");
    t.add_field(u32_field("magic").with_comment("0xCAFEBABE"));
    t.add_field(u16_field("minor_version"));
    t.add_field(u16_field("major_version").with_comment("52=Java8, 55=Java11, 61=Java17"));
    t.add_field(u16_field("constant_pool_count"));
    t
}

/// Windows PE32+ load configuration directory (abbreviated).
#[must_use]
pub fn template_pe_load_config() -> Template {
    let mut t = Template::new(
        "PE_LoadConfig",
        "PE32+ Load Configuration directory (abbrev.)",
    );
    t.add_field(u32_field("Size"));
    t.add_field(u32_field("TimeDateStamp"));
    t.add_field(u16_field("MajorVersion"));
    t.add_field(u16_field("MinorVersion"));
    t.add_field(u32_field("GlobalFlagsClear"));
    t.add_field(u32_field("GlobalFlagsSet"));
    t.add_field(u32_field("CriticalSectionDefaultTimeout"));
    t.add_field(u64_field("DeCommitFreeBlockThreshold"));
    t.add_field(u64_field("DeCommitTotalFreeThreshold"));
    t
}

/// Windows PE debug directory entry.
#[must_use]
pub fn template_pe_debug_dir() -> Template {
    let mut t = Template::new("PE_DebugDir", "PE debug directory entry");
    t.add_field(u32_field("Characteristics").with_comment("reserved, 0"));
    t.add_field(u32_field("TimeDateStamp"));
    t.add_field(u16_field("MajorVersion"));
    t.add_field(u16_field("MinorVersion"));
    t.add_field(u32_field("Type").with_comment("IMAGE_DEBUG_TYPE_*"));
    t.add_field(u32_field("SizeOfData"));
    t.add_field(u32_field("AddressOfRawData").with_comment("relative to image base"));
    t.add_field(u32_field("PointerToRawData").with_comment("file offset"));
    t
}

/// NE (New Executable, 16-bit Windows) header.
#[must_use]
pub fn template_ne_header() -> Template {
    let mut t = Template::new("NE_Header", "16-bit New Executable header");
    t.add_field(u16_field("ne_magic").with_comment("0x454E = 'NE'"));
    t.add_field(
        FieldDef::new("ne_ver", TemplateType::Primitive(DataType::U8))
            .with_comment("linker version"),
    );
    t.add_field(
        FieldDef::new("ne_rev", TemplateType::Primitive(DataType::U8))
            .with_comment("linker revision"),
    );
    t.add_field(u16_field("ne_enttab").with_comment("offset to entry table"));
    t.add_field(u16_field("ne_cbenttab").with_comment("entry table size"));
    t.add_field(u32_field("ne_crc").with_comment("file checksum"));
    t.add_field(u16_field("ne_flags").with_comment("module flags"));
    t.add_field(u16_field("ne_autodata").with_comment("automatic data segment number"));
    t
}

// ─────────────────────────────────────────────────────────────────────────────
// TemplateFieldSearchIndex — fast field lookup by name prefix
// ─────────────────────────────────────────────────────────────────────────────

/// An index for fast field lookup by name prefix.
#[derive(Debug, Clone, Default)]
pub struct TemplateFieldSearchIndex {
    /// (name_lower, field_path, offset, size) tuples.
    entries: Vec<(String, String, usize, usize)>,
}

impl TemplateFieldSearchIndex {
    /// Create an empty index.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Populate from a list of `TemplateField`s.
    pub fn build_from_fields(&mut self, fields: &[TemplateField]) {
        for f in fields {
            self.entries
                .push((f.name.to_lowercase(), f.path.clone(), f.offset, f.size));
        }
    }

    /// Find all entries whose name contains `query` (case-insensitive).
    #[must_use]
    pub fn search(&self, query: &str) -> Vec<&(String, String, usize, usize)> {
        let q = query.to_lowercase();
        self.entries
            .iter()
            .filter(|(name, _, _, _)| name.contains(q.as_str()))
            .collect()
    }

    /// Find the entry at a byte offset.
    #[must_use]
    pub fn at_offset(&self, offset: usize) -> Vec<&(String, String, usize, usize)> {
        self.entries
            .iter()
            .filter(|(_, _, o, s)| offset >= *o && offset < *o + *s)
            .collect()
    }

    /// Number of indexed entries.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` if empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TemplateDiff — find structural differences between two parsed results
// ─────────────────────────────────────────────────────────────────────────────

/// Difference kind between two corresponding fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FieldDiffKind {
    /// Values differ.
    ValueDiff,
    /// Field present in left only.
    LeftOnly,
    /// Field present in right only.
    RightOnly,
    /// Identical.
    Same,
}

/// A difference between two parsed struct results.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldDiff {
    pub path: String,
    pub kind: FieldDiffKind,
    pub left_value: Option<String>,
    pub right_value: Option<String>,
}

/// Compare two `ParsedStruct` results field by field.
#[must_use]
pub fn diff_parsed_structs(left: &ParsedStruct, right: &ParsedStruct) -> Vec<FieldDiff> {
    let mut diffs = Vec::new();
    // Build lookup maps keyed by field name.
    let left_map: std::collections::HashMap<&str, &ParsedField> =
        left.fields.iter().map(|f| (f.name.as_str(), f)).collect();
    let right_map: std::collections::HashMap<&str, &ParsedField> =
        right.fields.iter().map(|f| (f.name.as_str(), f)).collect();

    let value_str = |f: &ParsedField| -> String { format!("{:?}", f.value) };

    // Find left-only and value diffs.
    for (name, lf) in &left_map {
        match right_map.get(name) {
            Some(rf) => {
                let lv = value_str(lf);
                let rv = value_str(rf);
                let kind = if lv == rv {
                    FieldDiffKind::Same
                } else {
                    FieldDiffKind::ValueDiff
                };
                if kind != FieldDiffKind::Same {
                    diffs.push(FieldDiff {
                        path: (*name).to_owned(),
                        kind,
                        left_value: Some(lv),
                        right_value: Some(rv),
                    });
                }
            }
            None => diffs.push(FieldDiff {
                path: (*name).to_owned(),
                kind: FieldDiffKind::LeftOnly,
                left_value: Some(value_str(lf)),
                right_value: None,
            }),
        }
    }
    // Find right-only.
    for (name, rf) in &right_map {
        if !left_map.contains_key(name) {
            diffs.push(FieldDiff {
                path: (*name).to_owned(),
                kind: FieldDiffKind::RightOnly,
                left_value: None,
                right_value: Some(value_str(rf)),
            });
        }
    }
    diffs.sort_by(|a, b| a.path.cmp(&b.path));
    diffs
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests for new templates and utilities
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests_expanded4 {
    use super::*;

    #[test]
    fn test_elf32_sym2_field_count() {
        let t = template_elf32_sym2();
        assert_eq!(t.fields.len(), 6);
        assert_eq!(t.fields[0].name, "st_name");
    }

    #[test]
    fn test_elf64_sym_v2_field_count() {
        let t = template_elf64_sym_v2();
        assert_eq!(t.fields.len(), 6);
        assert_eq!(t.fields[4].name, "st_value");
    }

    #[test]
    fn test_elf64_rela_v2_field_count() {
        let t = template_elf64_rela_v2();
        assert_eq!(t.fields.len(), 3);
        assert_eq!(t.fields[0].name, "r_offset");
    }

    #[test]
    fn test_coff_string_table_fields() {
        let t = template_coff_string_table();
        assert_eq!(t.fields.len(), 1);
    }

    #[test]
    fn test_coff_reloc_v2_fields() {
        let t = template_coff_reloc_v2();
        assert_eq!(t.fields.len(), 3);
        assert_eq!(t.fields[2].name, "Type");
    }

    #[test]
    fn test_wasm_section_fields() {
        let t = template_wasm_section();
        assert_eq!(t.fields.len(), 2);
        assert_eq!(t.fields[0].name, "id");
    }

    #[test]
    fn test_macho_fat_header_fields() {
        let t = template_macho_fat_header();
        assert_eq!(t.fields.len(), 2);
        assert_eq!(t.fields[0].name, "magic");
    }

    #[test]
    fn test_macho_fat_arch_fields() {
        let t = template_macho_fat_arch();
        assert_eq!(t.fields.len(), 5);
        assert_eq!(t.fields[4].name, "align");
    }

    #[test]
    fn test_java_class_header_fields() {
        let t = template_java_class_header();
        assert_eq!(t.fields.len(), 4);
        assert_eq!(t.fields[0].name, "magic");
    }

    #[test]
    fn test_pe_load_config_fields() {
        let t = template_pe_load_config();
        assert_eq!(t.fields.len(), 9);
        assert_eq!(t.fields[0].name, "Size");
    }

    #[test]
    fn test_pe_debug_dir_fields() {
        let t = template_pe_debug_dir();
        assert_eq!(t.fields.len(), 8);
        assert_eq!(t.fields[6].name, "AddressOfRawData");
    }

    #[test]
    fn test_ne_header_fields() {
        let t = template_ne_header();
        assert_eq!(t.fields.len(), 8);
        assert_eq!(t.fields[0].name, "ne_magic");
    }

    // ── TemplateFieldSearchIndex ──────────────────────────────────────────────

    #[test]
    fn test_search_index_build_and_query() {
        let fields = vec![
            TemplateField::new("st_name", "st_name", 0, 4, "0x0001"),
            TemplateField::new("st_value", "st_value", 4, 4, "0x1000"),
            TemplateField::new("st_size", "st_size", 8, 4, "0x0014"),
        ];
        let mut idx = TemplateFieldSearchIndex::new();
        idx.build_from_fields(&fields);
        assert_eq!(idx.len(), 3);
        let hits = idx.search("value");
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn test_search_index_at_offset() {
        let fields = vec![
            TemplateField::new("magic", "magic", 0, 4, "0x7F454C46"),
            TemplateField::new("class", "class", 4, 1, "0x02"),
        ];
        let mut idx = TemplateFieldSearchIndex::new();
        idx.build_from_fields(&fields);
        let hits = idx.at_offset(3);
        assert_eq!(hits.len(), 1); // only 'magic' covers offset 3
        let hits2 = idx.at_offset(4);
        assert_eq!(hits2.len(), 1); // only 'class' covers offset 4
    }

    #[test]
    fn test_search_index_case_insensitive() {
        let fields = vec![TemplateField::new(
            "MagicBytes",
            "MagicBytes",
            0,
            4,
            "0xDEAD",
        )];
        let mut idx = TemplateFieldSearchIndex::new();
        idx.build_from_fields(&fields);
        let hits = idx.search("magic");
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn test_search_index_empty() {
        let idx = TemplateFieldSearchIndex::new();
        assert!(idx.is_empty());
        assert_eq!(idx.search("anything").len(), 0);
    }

    // ── TemplateDiff ──────────────────────────────────────────────────────────

    #[test]
    fn test_diff_identical_structs() {
        let mut data = vec![0u8; 16];
        data[0] = 0x01; // DT_NEEDED
        let t = template_elf64_dyn();
        let buf = rustre_hex::HexBuffer::new(data.clone());
        let applier = TemplateApplier::new(&buf);
        let left = applier.apply(&t, 0).unwrap();
        let right = applier.apply(&t, 0).unwrap();
        let diffs = diff_parsed_structs(&left, &right);
        assert!(diffs.is_empty());
    }

    #[test]
    fn test_diff_structs_value_diff() {
        let t = template_coff_reloc_v2();
        let mut left_data = vec![0u8; 10];
        let mut right_data = vec![0u8; 10];
        left_data[4] = 0x01;
        right_data[4] = 0x02;
        let buf_left = rustre_hex::HexBuffer::new(left_data.clone());
        let buf_right = rustre_hex::HexBuffer::new(right_data.clone());
        let left = TemplateApplier::new(&buf_left).apply(&t, 0).unwrap();
        let right = TemplateApplier::new(&buf_right).apply(&t, 0).unwrap();
        let diffs = diff_parsed_structs(&left, &right);
        assert!(diffs.iter().any(|d| d.kind == FieldDiffKind::ValueDiff));
    }

    #[test]
    fn test_template_stats_ne_header() {
        let t = template_ne_header();
        let stats = template_stats(&t);
        assert_eq!(stats.top_level_fields, 8);
        assert!(stats.min_fixed_size >= 14);
    }

    #[test]
    fn test_template_stats_wasm() {
        let t = template_wasm_section();
        let stats = template_stats(&t);
        assert_eq!(stats.total_fields, 2);
    }

    #[test]
    fn test_template_stats_java() {
        let t = template_java_class_header();
        let stats = template_stats(&t);
        assert_eq!(stats.total_fields, 4);
    }

    #[test]
    fn test_template_library_all_names() {
        let lib = TemplateRegistry::with_builtins();
        let names = lib.names();
        // Verify a few expected names
        assert!(names.iter().any(|n| n.contains("ELF")));
        assert!(names.iter().any(|n| n.contains("PE")));
    }

    #[test]
    fn test_template_library_get_missing() {
        let lib = TemplateRegistry::with_builtins();
        assert!(lib.get("NonExistentTemplate").is_none());
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PE_TEMPLATE — 010 Editor-style template source (string constant)
// ─────────────────────────────────────────────────────────────────────────────

/// 010 Editor-style template source for PE (Portable Executable) files.
///
/// The text is informational / documentation; the actual parsing is done by
/// the strongly-typed [`apply_pe_template`] function below.
pub const PE_TEMPLATE: &str = r#"
// 010 Editor-style PE template
// Parses the DOS header, PE file header, and optional header.

typedef struct {
    BYTE  e_magic[2];       // MZ signature
    WORD  e_cblp;
    WORD  e_cp;
    WORD  e_crlc;
    WORD  e_cparhdr;
    WORD  e_minalloc;
    WORD  e_maxalloc;
    WORD  e_ss;
    WORD  e_sp;
    WORD  e_csum;
    WORD  e_ip;
    WORD  e_cs;
    WORD  e_lfarlc;
    WORD  e_ovno;
    BYTE  e_res[8];
    WORD  e_oemid;
    WORD  e_oeminfo;
    BYTE  e_res2[20];
    DWORD e_lfanew;         // File offset of PE header
} DOS_HEADER;

typedef struct {
    BYTE  Signature[4];     // "PE\0\0"
    WORD  Machine;
    WORD  NumberOfSections;
    DWORD TimeDateStamp;
    DWORD PointerToSymbolTable;
    DWORD NumberOfSymbols;
    WORD  SizeOfOptionalHeader;
    WORD  Characteristics;
} PE_HEADER;

typedef struct {
    WORD  Magic;            // 0x010B = PE32, 0x020B = PE32+
    BYTE  MajorLinkerVersion;
    BYTE  MinorLinkerVersion;
    DWORD SizeOfCode;
    DWORD SizeOfInitializedData;
    DWORD SizeOfUninitializedData;
    DWORD AddressOfEntryPoint;
    DWORD BaseOfCode;
    DWORD BaseOfData;       // PE32 only
    DWORD ImageBase;
    DWORD SectionAlignment;
    DWORD FileAlignment;
    WORD  MajorOperatingSystemVersion;
    WORD  MinorOperatingSystemVersion;
    WORD  MajorImageVersion;
    WORD  MinorImageVersion;
    WORD  MajorSubsystemVersion;
    WORD  MinorSubsystemVersion;
    DWORD Win32VersionValue;
    DWORD SizeOfImage;
    DWORD SizeOfHeaders;
    DWORD CheckSum;
    WORD  Subsystem;
    WORD  DllCharacteristics;
    DWORD SizeOfStackReserve;
    DWORD SizeOfStackCommit;
    DWORD SizeOfHeapReserve;
    DWORD SizeOfHeapCommit;
    DWORD LoaderFlags;
    DWORD NumberOfRvaAndSizes;
} OPTIONAL_HEADER;

// Entry point
DOS_HEADER dos_header;
if (dos_header.e_magic[0] == 'M' && dos_header.e_magic[1] == 'Z') {
    Printf("DOS header OK, PE offset = %d\n", dos_header.e_lfanew);
    FSeek(dos_header.e_lfanew);
    PE_HEADER pe_header;
    if (pe_header.Signature[0] == 'P' && pe_header.Signature[1] == 'E') {
        Printf("PE header OK, machine = 0x%04X\n", pe_header.Machine);
        OPTIONAL_HEADER opt_header;
        Printf("Optional header magic = 0x%04X\n", opt_header.Magic);
    }
}
"#;

// ─────────────────────────────────────────────────────────────────────────────
// TemplateResult — structured result of a complete template application
// ─────────────────────────────────────────────────────────────────────────────

/// The structured result of applying a PE template (or any named set of
/// sub-templates) to a binary buffer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateResult {
    /// Human-readable name of the top-level template applied.
    pub template_name: String,
    /// Per-section parse results, keyed by section name (e.g. `"dos_header"`).
    pub sections: Vec<(String, ParsedStruct)>,
    /// Any log/Printf messages emitted during parsing.
    pub log: Vec<String>,
}

impl TemplateResult {
    /// Serialise the result to a [`serde_json::Value`].
    ///
    /// Each section becomes a JSON object whose keys are field names and whose
    /// values are the human-readable display strings produced by
    /// [`flatten_parsed`].
    #[must_use]
    pub fn to_json(&self) -> serde_json::Value {
        let sections_json: serde_json::Map<String, serde_json::Value> = self
            .sections
            .iter()
            .map(|(name, parsed)| {
                let flat = flatten_parsed(parsed);
                let fields_json: serde_json::Map<String, serde_json::Value> = flat
                    .iter()
                    .map(|f| (f.path.clone(), serde_json::Value::String(f.display.clone())))
                    .collect();
                (name.clone(), serde_json::Value::Object(fields_json))
            })
            .collect();

        serde_json::json!({
            "template": self.template_name,
            "sections": sections_json,
            "log": self.log,
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// apply_pe_template — convenience entry point
// ─────────────────────────────────────────────────────────────────────────────

/// Parse a PE binary and return a [`TemplateResult`] containing the DOS
/// header, PE file header, and optional header.
///
/// The function validates the MZ and PE signatures and follows `e_lfanew` to
/// locate the PE header, mirroring what the [`PE_TEMPLATE`] source describes.
///
/// # Errors
/// Returns a [`TemplateError`] if the buffer is too small, a signature is
/// missing, or any field cannot be read.
pub fn apply_pe_template(data: &[u8]) -> Result<TemplateResult, TemplateError> {
    let buf = rustre_hex::HexBuffer::new(data.to_vec());
    let applier = TemplateApplier::new(&buf);

    let mut result = TemplateResult {
        template_name: "PE".to_string(),
        sections: Vec::new(),
        log: Vec::new(),
    };

    // ── DOS header ────────────────────────────────────────────────────────────
    let dos_tmpl = template_mz();
    let dos_parsed = applier
        .apply(&dos_tmpl, 0)
        .map_err(|e| TemplateError::Field("dos_header".to_string(), e.to_string()))?;

    // Validate MZ signature
    let mz_ok = dos_parsed
        .fields
        .iter()
        .find(|f| f.name == "e_magic")
        .and_then(|f| {
            if let rustre_hex::TypedValue::Bytes(ref b) = f.value {
                Some(b.len() >= 2 && b[0] == b'M' && b[1] == b'Z')
            } else {
                None
            }
        })
        .unwrap_or(false);

    if !mz_ok {
        return Err(TemplateError::Field(
            "e_magic".to_string(),
            "not a valid MZ executable (missing MZ signature)".to_string(),
        ));
    }
    result.log.push("DOS header OK".to_string());

    // Read e_lfanew (file offset of PE header)
    let e_lfanew = dos_parsed.field_as_u64("e_lfanew").ok_or_else(|| {
        TemplateError::Field("e_lfanew".to_string(), "field not found".to_string())
    })? as usize;

    result
        .log
        .push(format!("PE header at offset 0x{e_lfanew:X}"));
    result.sections.push(("dos_header".to_string(), dos_parsed));

    // ── PE file header ────────────────────────────────────────────────────────
    let pe_tmpl = template_pe_coff();
    let pe_parsed = applier
        .apply(&pe_tmpl, e_lfanew)
        .map_err(|e| TemplateError::Field("pe_header".to_string(), e.to_string()))?;

    // Validate PE\0\0 signature
    let pe_ok = pe_parsed
        .fields
        .iter()
        .find(|f| f.name == "Signature")
        .and_then(|f| {
            if let rustre_hex::TypedValue::Bytes(ref b) = f.value {
                Some(b.len() >= 4 && b[0] == b'P' && b[1] == b'E' && b[2] == 0 && b[3] == 0)
            } else {
                None
            }
        })
        .unwrap_or(false);

    if !pe_ok {
        return Err(TemplateError::Field(
            "Signature".to_string(),
            "PE\\0\\0 signature not found at e_lfanew".to_string(),
        ));
    }
    result.log.push("PE signature OK".to_string());

    // Offset just after the PE COFF header (4-byte sig + 20-byte COFF = 24)
    let opt_hdr_offset = e_lfanew + 4 + 20; // "PE\0\0" + IMAGE_FILE_HEADER
    result.sections.push(("pe_header".to_string(), pe_parsed));

    // ── Optional header ───────────────────────────────────────────────────────
    let opt_tmpl = template_pe_optional_header();
    let opt_parsed = applier
        .apply(&opt_tmpl, opt_hdr_offset)
        .map_err(|e| TemplateError::Field("optional_header".to_string(), e.to_string()))?;

    let magic = opt_parsed.field_as_u64("Magic").unwrap_or(0);
    result.log.push(format!(
        "Optional header magic = {magic:#06X} ({})",
        match magic {
            0x010B => "PE32",
            0x020B => "PE32+",
            0x0107 => "ROM",
            _ => "unknown",
        }
    ));
    result
        .sections
        .push(("optional_header".to_string(), opt_parsed));

    Ok(result)
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests for TemplateResult / apply_pe_template
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests_pe_template {
    use super::*;

    /// Build a minimal but structurally valid PE32 binary stub (just headers).
    fn minimal_pe32() -> Vec<u8> {
        let mut data = vec![0u8; 512];
        // DOS header: MZ magic + e_lfanew at offset 0x3C = 0x40
        data[0] = b'M';
        data[1] = b'Z';
        data[0x3C] = 0x40; // e_lfanew = 0x40

        // PE signature at 0x40
        data[0x40] = b'P';
        data[0x41] = b'E';
        data[0x42] = 0;
        data[0x43] = 0;

        // COFF file header (20 bytes) at 0x44
        data[0x44] = 0x4C; // Machine = 0x014C (x86)
        data[0x45] = 0x01;
        data[0x46] = 0x01; // NumberOfSections = 1

        // Optional header at 0x58 (0x40 + 4 + 20)
        data[0x58] = 0x0B; // Magic = 0x010B (PE32)
        data[0x59] = 0x01;

        data
    }

    #[test]
    fn test_apply_pe_template_ok() {
        let data = minimal_pe32();
        let result = apply_pe_template(&data).unwrap();
        assert_eq!(result.template_name, "PE");
        assert_eq!(result.sections.len(), 3);
        assert_eq!(result.sections[0].0, "dos_header");
        assert_eq!(result.sections[1].0, "pe_header");
        assert_eq!(result.sections[2].0, "optional_header");
    }

    #[test]
    fn test_apply_pe_template_bad_mz() {
        let data = vec![0u8; 128];
        let err = apply_pe_template(&data).unwrap_err();
        assert!(err.to_string().contains("MZ") || err.to_string().contains("e_magic"));
    }

    #[test]
    fn test_apply_pe_template_bad_pe_sig() {
        let mut data = vec![0u8; 256];
        data[0] = b'M';
        data[1] = b'Z';
        data[0x3C] = 0x40;
        // No PE\0\0 at 0x40 — leave it as zeros
        let err = apply_pe_template(&data).unwrap_err();
        assert!(err.to_string().contains("PE") || err.to_string().contains("Signature"));
    }

    #[test]
    fn test_template_result_to_json_structure() {
        let data = minimal_pe32();
        let result = apply_pe_template(&data).unwrap();
        let json = result.to_json();
        assert_eq!(json["template"], "PE");
        assert!(json["sections"]["dos_header"].is_object());
        assert!(json["sections"]["pe_header"].is_object());
        assert!(json["sections"]["optional_header"].is_object());
        assert!(json["log"].is_array());
    }

    #[test]
    fn test_template_result_to_json_dos_magic() {
        let data = minimal_pe32();
        let result = apply_pe_template(&data).unwrap();
        let json = result.to_json();
        // e_magic field should be present in the dos_header section
        assert!(json["sections"]["dos_header"]["e_magic"].is_string());
    }

    #[test]
    fn test_pe_template_constant_non_empty() {
        assert!(!PE_TEMPLATE.is_empty());
        assert!(PE_TEMPLATE.contains("DOS_HEADER"));
        assert!(PE_TEMPLATE.contains("PE_HEADER"));
        assert!(PE_TEMPLATE.contains("OPTIONAL_HEADER"));
    }

    #[test]
    fn test_pe_template_contains_typedef() {
        assert!(PE_TEMPLATE.contains("typedef struct"));
    }

    #[test]
    fn test_pe_template_contains_array() {
        // Array field: BYTE e_magic[2]
        assert!(PE_TEMPLATE.contains("e_magic[2]"));
    }

    #[test]
    fn test_pe_template_contains_conditional() {
        assert!(PE_TEMPLATE.contains("if ("));
    }

    #[test]
    fn test_pe_template_contains_printf() {
        assert!(PE_TEMPLATE.contains("Printf("));
    }
}
