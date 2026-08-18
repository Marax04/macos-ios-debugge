// attribute_reader.rs — .NET custom attribute blob decoder
// Decodes CustomAttribute blobs per ECMA-335 §II.23.3, resolves constructors,
// unpacks positional and named arguments with type reconstruction.

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

// ─── Fixed argument types ─────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum FixedArg {
    Bool(bool),
    I1(i8),
    U1(u8),
    I2(i16),
    U2(u16),
    I4(i32),
    U4(u32),
    I8(i64),
    U8(u64),
    R4(f32),
    R8(f64),
    Char(char),
    String(Option<String>),
    Type(Option<String>),   // SerString as System.Type
    Enum(String, i64),      // enum type name + underlying value
    Array(FixedArgType, Vec<Self>),
    Boxed(Box<Self>),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FixedArgType {
    Bool,
    I1, U1, I2, U2, I4, U4, I8, U8,
    R4, R8,
    Char,
    String,
    Type,
    Enum(String),
    Object,
}

impl FixedArgType {
    pub fn from_ser_type_byte(b: u8, enum_type: Option<&str>) -> Option<Self> {
        match b {
            0x02 => Some(Self::Bool),
            0x03 => Some(Self::Char),
            0x04 => Some(Self::I1),
            0x05 => Some(Self::U1),
            0x06 => Some(Self::I2),
            0x07 => Some(Self::U2),
            0x08 => Some(Self::I4),
            0x09 => Some(Self::U4),
            0x0A => Some(Self::I8),
            0x0B => Some(Self::U8),
            0x0C => Some(Self::R4),
            0x0D => Some(Self::R8),
            0x0E => Some(Self::String),
            0x50 => Some(Self::Type),
            0x55 => Some(Self::Enum(enum_type.unwrap_or("").to_string())),
            0x51 => Some(Self::Object),
            _ => None,
        }
    }
}

impl fmt::Display for FixedArg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bool(v) => write!(f, "{v}"),
            Self::I1(v) => write!(f, "{v}"),
            Self::U1(v) => write!(f, "{v}"),
            Self::I2(v) => write!(f, "{v}"),
            Self::U2(v) => write!(f, "{v}"),
            Self::I4(v) => write!(f, "{v}"),
            Self::U4(v) => write!(f, "{v}"),
            Self::I8(v) => write!(f, "{v}"),
            Self::U8(v) => write!(f, "{v}"),
            Self::R4(v) => write!(f, "{v}"),
            Self::R8(v) => write!(f, "{v}"),
            Self::Char(c) => write!(f, "'{c}'"),
            Self::String(Some(s)) => write!(f, "\"{s}\""),
            Self::String(None) => write!(f, "null"),
            Self::Type(Some(t)) => write!(f, "typeof({t})"),
            Self::Type(None) => write!(f, "typeof(null)"),
            Self::Enum(ty, v) => write!(f, "({ty}){v}L"),
            Self::Array(_, items) => {
                let parts: Vec<_> = items.iter().map(|i| i.to_string()).collect();
                write!(f, "[{}]", parts.join(", "))
            }
            Self::Boxed(inner) => write!(f, "box({inner})"),
        }
    }
}

// ─── Named argument ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NamedArg {
    pub kind: NamedArgKind,
    pub name: String,
    pub value: FixedArg,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NamedArgKind {
    Field,
    Property,
}

impl fmt::Display for NamedArg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let prefix = match self.kind { NamedArgKind::Field => "field", NamedArgKind::Property => "property" };
        write!(f, "{} {} = {}", prefix, self.name, self.value)
    }
}

// ─── Decoded custom attribute ────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecodedAttribute {
    pub attribute_type: String,
    pub constructor_token: u32,
    pub positional_args: Vec<FixedArg>,
    pub named_args: Vec<NamedArg>,
    pub raw_blob_offset: usize,
    pub raw_blob_len: usize,
}

impl DecodedAttribute {
    pub fn get_named_field(&self, name: &str) -> Option<&FixedArg> {
        self.named_args.iter().find(|a| a.kind == NamedArgKind::Field && a.name == name).map(|a| &a.value)
    }

    pub fn get_named_property(&self, name: &str) -> Option<&FixedArg> {
        self.named_args.iter().find(|a| a.kind == NamedArgKind::Property && a.name == name).map(|a| &a.value)
    }

    pub fn get_positional(&self, index: usize) -> Option<&FixedArg> {
        self.positional_args.get(index)
    }

    pub fn positional_as_string(&self, index: usize) -> Option<&str> {
        match self.positional_args.get(index) {
            Some(FixedArg::String(Some(s))) => Some(s.as_str()),
            _ => None,
        }
    }

    pub fn positional_as_i32(&self, index: usize) -> Option<i32> {
        match self.positional_args.get(index) {
            Some(FixedArg::I4(v)) => Some(*v),
            Some(FixedArg::I2(v)) => Some(i32::from(*v)),
            Some(FixedArg::I1(v)) => Some(i32::from(*v)),
            _ => None,
        }
    }

    pub fn positional_as_bool(&self, index: usize) -> Option<bool> {
        match self.positional_args.get(index) {
            Some(FixedArg::Bool(v)) => Some(*v),
            _ => None,
        }
    }

    pub fn to_source_like(&self) -> String {
        let mut parts: Vec<String> = self.positional_args.iter().map(|a| a.to_string()).collect();
        for na in &self.named_args { parts.push(format!("{} = {}", na.name, na.value)); }
        if parts.is_empty() {
            format!("[{}]", self.attribute_type)
        } else {
            format!("[{}({})]", self.attribute_type, parts.join(", "))
        }
    }
}

// ─── Constructor parameter descriptor ───────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CtorParam {
    pub name: String,
    pub param_type: FixedArgType,
}

// ─── Attribute constructor descriptor ───────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttributeCtorDescriptor {
    pub token: u32,
    pub declaring_type: String,
    pub params: Vec<CtorParam>,
}

// ─── Attribute blob reader ────────────────────────────────────────────────────

pub struct AttributeBlobReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> AttributeBlobReader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    pub fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }

    pub fn peek_byte(&self) -> Option<u8> {
        self.data.get(self.pos).copied()
    }

    fn read_byte(&mut self) -> Result<u8> {
        if self.pos >= self.data.len() {
            bail!("AttributeBlobReader: unexpected end of blob at offset {}", self.pos);
        }
        let b = self.data[self.pos];
        self.pos += 1;
        Ok(b)
    }

    fn read_u16_le(&mut self) -> Result<u16> {
        let lo = u16::from(self.read_byte()?);
        let hi = u16::from(self.read_byte()?);
        Ok(lo | (hi << 8))
    }

    fn read_u32_le(&mut self) -> Result<u32> {
        let b0 = u32::from(self.read_byte()?);
        let b1 = u32::from(self.read_byte()?);
        let b2 = u32::from(self.read_byte()?);
        let b3 = u32::from(self.read_byte()?);
        Ok(b0 | (b1 << 8) | (b2 << 16) | (b3 << 24))
    }

    fn read_u64_le(&mut self) -> Result<u64> {
        let lo = u64::from(self.read_u32_le()?);
        let hi = u64::from(self.read_u32_le()?);
        Ok(lo | (hi << 32))
    }

    fn read_f32(&mut self) -> Result<f32> {
        let bits = self.read_u32_le()?;
        Ok(f32::from_bits(bits))
    }

    fn read_f64(&mut self) -> Result<f64> {
        let bits = self.read_u64_le()?;
        Ok(f64::from_bits(bits))
    }

    /// Read a serialized string (§II.23.3: packed length + UTF-8 bytes, or 0xFF for null)
    pub fn read_ser_string(&mut self) -> Result<Option<String>> {
        let first = self.read_byte()?;
        if first == 0xFF {
            return Ok(None);
        }
        // decode packed length
        let len = if first & 0x80 == 0 {
            first as usize
        } else if first & 0xC0 == 0x80 {
            let b1 = self.read_byte()? as usize;
            (((first & 0x3F) as usize) << 8) | b1
        } else {
            let b1 = self.read_byte()? as usize;
            let b2 = self.read_byte()? as usize;
            let b3 = self.read_byte()? as usize;
            (((first & 0x1F) as usize) << 24) | (b1 << 16) | (b2 << 8) | b3
        };
        if self.pos + len > self.data.len() {
            bail!("AttributeBlobReader: ser_string length {len} exceeds remaining blob");
        }
        let s = std::str::from_utf8(&self.data[self.pos..self.pos + len])
            .context("invalid UTF-8 in ser_string")?
            .to_string();
        self.pos += len;
        Ok(Some(s))
    }

    pub fn read_fixed_arg(&mut self, arg_type: &FixedArgType) -> Result<FixedArg> {
        Ok(match arg_type {
            FixedArgType::Bool => FixedArg::Bool(self.read_byte()? != 0),
            FixedArgType::I1 => FixedArg::I1(self.read_byte()? as i8),
            FixedArgType::U1 => FixedArg::U1(self.read_byte()?),
            FixedArgType::I2 => FixedArg::I2(self.read_u16_le()? as i16),
            FixedArgType::U2 => FixedArg::U2(self.read_u16_le()?),
            FixedArgType::I4 => FixedArg::I4(self.read_u32_le()? as i32),
            FixedArgType::U4 => FixedArg::U4(self.read_u32_le()?),
            FixedArgType::I8 => FixedArg::I8(self.read_u64_le()? as i64),
            FixedArgType::U8 => FixedArg::U8(self.read_u64_le()?),
            FixedArgType::R4 => FixedArg::R4(self.read_f32()?),
            FixedArgType::R8 => FixedArg::R8(self.read_f64()?),
            FixedArgType::Char => {
                let v = self.read_u16_le()?;
                let c = char::from_u32(u32::from(v)).unwrap_or('\u{FFFD}');
                FixedArg::Char(c)
            }
            FixedArgType::String => FixedArg::String(self.read_ser_string()?),
            FixedArgType::Type => FixedArg::Type(self.read_ser_string()?),
            FixedArgType::Enum(type_name) => {
                // Treat as I4 by default (most common underlying type)
                let v = i64::from(self.read_u32_le()? as i32);
                FixedArg::Enum(type_name.clone(), v)
            }
            FixedArgType::Object => {
                // BoxedObject: read SerType byte then value
                let type_byte = self.read_byte()?;
                let inner_type = FixedArgType::from_ser_type_byte(type_byte, None)
                    .unwrap_or(FixedArgType::I4);
                let inner = self.read_fixed_arg(&inner_type)?;
                FixedArg::Boxed(Box::new(inner))
            }
        })
    }

    /// Read a named argument (field or property).
    pub fn read_named_arg(&mut self) -> Result<NamedArg> {
        let kind_byte = self.read_byte()?;
        let kind = match kind_byte {
            0x53 => NamedArgKind::Field,
            0x54 => NamedArgKind::Property,
            other => bail!("AttributeBlobReader: invalid named arg kind byte 0x{other:02x}"),
        };

        let type_byte = self.read_byte()?;
        let enum_type_name = if type_byte == 0x55 {
            self.read_ser_string()?.unwrap_or_default()
        } else {
            String::new()
        };

        let arg_type = FixedArgType::from_ser_type_byte(type_byte, if enum_type_name.is_empty() { None } else { Some(&enum_type_name) })
            .unwrap_or(FixedArgType::I4);

        let name = self.read_ser_string()?.unwrap_or_default();
        let value = self.read_fixed_arg(&arg_type)?;

        Ok(NamedArg { kind, name, value })
    }

    /// Decode a complete CustomAttribute blob given the constructor descriptor.
    pub fn decode_attribute(&mut self, ctor: &AttributeCtorDescriptor) -> Result<DecodedAttribute> {
        // Prolog: 0x0001
        let prolog = self.read_u16_le().context("reading attribute prolog")?;
        if prolog != 0x0001 {
            bail!("AttributeBlobReader: expected prolog 0x0001, got 0x{prolog:04x}");
        }

        let mut positional_args = Vec::new();
        for param in &ctor.params {
            let arg = self.read_fixed_arg(&param.param_type)
                .with_context(|| format!("reading positional arg '{}'", param.name))?;
            positional_args.push(arg);
        }

        let num_named = self.read_u16_le().context("reading named arg count")?;
        let mut named_args = Vec::new();
        for _ in 0..num_named {
            let na = self.read_named_arg().context("reading named arg")?;
            named_args.push(na);
        }

        Ok(DecodedAttribute {
            attribute_type: ctor.declaring_type.clone(),
            constructor_token: ctor.token,
            positional_args,
            named_args,
            raw_blob_offset: 0,
            raw_blob_len: self.data.len(),
        })
    }
}

// ─── Well-known attribute detectors ─────────────────────────────────────────

pub mod well_known {
    use super::DecodedAttribute;

    pub fn is_obsolete(attr: &DecodedAttribute) -> bool {
        attr.attribute_type.ends_with("ObsoleteAttribute")
    }

    pub fn is_serializable(attr: &DecodedAttribute) -> bool {
        attr.attribute_type.ends_with("SerializableAttribute")
    }

    pub fn is_flags_enum(attr: &DecodedAttribute) -> bool {
        attr.attribute_type.ends_with("FlagsAttribute")
    }

    pub fn is_dll_import(attr: &DecodedAttribute) -> bool {
        attr.attribute_type.ends_with("DllImportAttribute")
    }

    pub fn get_dll_import_lib(attr: &DecodedAttribute) -> Option<&str> {
        if !is_dll_import(attr) { return None; }
        attr.positional_as_string(0)
    }

    pub fn is_marshal_as(attr: &DecodedAttribute) -> bool {
        attr.attribute_type.ends_with("MarshalAsAttribute")
    }

    pub fn get_obsolete_message(attr: &DecodedAttribute) -> Option<&str> {
        attr.positional_as_string(0)
    }

    pub fn is_error_obsolete(attr: &DecodedAttribute) -> bool {
        if !is_obsolete(attr) { return false; }
        attr.positional_as_bool(1).unwrap_or(false)
    }

    pub fn is_struct_layout(attr: &DecodedAttribute) -> bool {
        attr.attribute_type.ends_with("StructLayoutAttribute")
    }

    pub fn get_layout_kind(attr: &DecodedAttribute) -> Option<i32> {
        attr.positional_as_i32(0)
    }

    pub fn is_assembly_version(attr: &DecodedAttribute) -> bool {
        attr.attribute_type.ends_with("AssemblyVersionAttribute")
    }

    pub fn is_security_permission(attr: &DecodedAttribute) -> bool {
        attr.attribute_type.ends_with("SecurityPermissionAttribute")
    }

    pub fn is_in_param(attr: &DecodedAttribute) -> bool {
        attr.attribute_type.ends_with("InAttribute")
    }

    pub fn is_out_param(attr: &DecodedAttribute) -> bool {
        attr.attribute_type.ends_with("OutAttribute")
    }

    pub fn is_optional(attr: &DecodedAttribute) -> bool {
        attr.attribute_type.ends_with("OptionalAttribute")
    }

    pub fn is_param_array(attr: &DecodedAttribute) -> bool {
        attr.attribute_type.ends_with("ParamArrayAttribute")
    }

    pub fn is_extension(attr: &DecodedAttribute) -> bool {
        attr.attribute_type.ends_with("ExtensionAttribute")
    }

    pub fn is_async_state_machine(attr: &DecodedAttribute) -> bool {
        attr.attribute_type.ends_with("AsyncStateMachineAttribute")
    }

    pub fn is_compiler_generated(attr: &DecodedAttribute) -> bool {
        attr.attribute_type.ends_with("CompilerGeneratedAttribute")
    }

    pub fn is_debugger_step_through(attr: &DecodedAttribute) -> bool {
        attr.attribute_type.ends_with("DebuggerStepThroughAttribute")
    }
}

// ─── Attribute registry ───────────────────────────────────────────────────────

#[derive(Debug, Default)]
pub struct AttributeRegistry {
    by_type_name: HashMap<String, Vec<DecodedAttribute>>,
    by_target_token: HashMap<u32, Vec<DecodedAttribute>>,
    constructors: HashMap<u32, AttributeCtorDescriptor>,
}

impl AttributeRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register_ctor(&mut self, ctor: AttributeCtorDescriptor) {
        self.constructors.insert(ctor.token, ctor);
    }

    pub fn add_decoded(&mut self, target_token: u32, attr: DecodedAttribute) {
        self.by_type_name.entry(attr.attribute_type.clone()).or_default().push(attr.clone());
        self.by_target_token.entry(target_token).or_default().push(attr);
    }

    pub fn decode_and_register(&mut self, target_token: u32, ctor_token: u32, blob: &[u8], blob_offset: usize) -> Result<()> {
        let ctor = self.constructors.get(&ctor_token)
            .cloned()
            .with_context(|| format!("no constructor descriptor for token 0x{ctor_token:08x}"))?;
        let mut reader = AttributeBlobReader::new(blob);
        let mut decoded = reader.decode_attribute(&ctor)?;
        decoded.raw_blob_offset = blob_offset;
        decoded.raw_blob_len = blob.len();
        self.add_decoded(target_token, decoded);
        Ok(())
    }

    pub fn for_token(&self, token: u32) -> &[DecodedAttribute] {
        self.by_target_token.get(&token).map_or(&[], |v| v.as_slice())
    }

    pub fn by_type(&self, type_name: &str) -> &[DecodedAttribute] {
        self.by_type_name.get(type_name).map_or(&[], |v| v.as_slice())
    }

    pub fn all_dll_imports(&self) -> Vec<(&str, &DecodedAttribute)> {
        self.by_type_name.iter()
            .filter(|(name, _)| name.ends_with("DllImportAttribute"))
            .flat_map(|(_, attrs)| attrs.iter().map(|a| (well_known::get_dll_import_lib(a).unwrap_or(""), a)))
            .collect()
    }

    pub fn total_attribute_count(&self) -> usize {
        self.by_target_token.values().map(|v| v.len()).sum()
    }

    pub fn types_with_attributes(&self) -> usize {
        self.by_target_token.len()
    }

    pub fn unique_attribute_types(&self) -> Vec<&str> {
        self.by_type_name.keys().map(|k| k.as_str()).collect()
    }
}

// ─── Attribute summary for a token ───────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttributeSummary {
    pub target_token: u32,
    pub count: usize,
    pub types: Vec<String>,
    pub has_obsolete: bool,
    pub has_dll_import: bool,
    pub has_compiler_generated: bool,
    pub source_like: Vec<String>,
}

impl AttributeSummary {
    pub fn from_attrs(target_token: u32, attrs: &[DecodedAttribute]) -> Self {
        let types: Vec<_> = attrs.iter().map(|a| a.attribute_type.clone()).collect();
        let has_obsolete = attrs.iter().any(well_known::is_obsolete);
        let has_dll_import = attrs.iter().any(well_known::is_dll_import);
        let has_compiler_generated = attrs.iter().any(well_known::is_compiler_generated);
        let source_like: Vec<_> = attrs.iter().map(|a| a.to_source_like()).collect();
        Self {
            target_token,
            count: attrs.len(),
            types,
            has_obsolete,
            has_dll_import,
            has_compiler_generated,
            source_like,
        }
    }
}

// ─── Attribute filter ─────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct AttributeFilter {
    type_name_contains: Vec<String>,
    require_positional_count: Option<usize>,
    require_named_arg: Option<String>,
}

impl AttributeFilter {
    pub fn new() -> Self {
        Self { type_name_contains: Vec::new(), require_positional_count: None, require_named_arg: None }
    }

    #[must_use]
    pub fn with_type_contains(mut self, fragment: &str) -> Self {
        self.type_name_contains.push(fragment.to_string());
        self
    }

    #[must_use]
    pub fn with_positional_count(mut self, count: usize) -> Self {
        self.require_positional_count = Some(count);
        self
    }

    #[must_use]
    pub fn with_named_arg(mut self, name: &str) -> Self {
        self.require_named_arg = Some(name.to_string());
        self
    }

    pub fn matches(&self, attr: &DecodedAttribute) -> bool {
        if !self.type_name_contains.is_empty() {
            let matches_type = self.type_name_contains.iter().any(|f| attr.attribute_type.contains(f.as_str()));
            if !matches_type { return false; }
        }
        if let Some(cnt) = self.require_positional_count
            && attr.positional_args.len() != cnt { return false; }
        if let Some(ref name) = self.require_named_arg {
            let has = attr.named_args.iter().any(|na| &na.name == name);
            if !has { return false; }
        }
        true
    }
}

impl Default for AttributeFilter {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Bulk attribute reader ────────────────────────────────────────────────────

pub struct BulkAttributeReader {
    registry: AttributeRegistry,
    errors: Vec<(u32, String)>,
}

impl BulkAttributeReader {
    pub fn new() -> Self {
        Self { registry: AttributeRegistry::new(), errors: Vec::new() }
    }

    pub fn register_ctor(&mut self, ctor: AttributeCtorDescriptor) {
        self.registry.register_ctor(ctor);
    }

    pub fn decode(&mut self, target_token: u32, ctor_token: u32, blob: &[u8], offset: usize) {
        if let Err(e) = self.registry.decode_and_register(target_token, ctor_token, blob, offset) {
            self.errors.push((target_token, e.to_string()));
        }
    }

    pub fn registry(&self) -> &AttributeRegistry {
        &self.registry
    }

    pub fn errors(&self) -> &[(u32, String)] {
        &self.errors
    }

    pub fn error_count(&self) -> usize {
        self.errors.len()
    }

    pub fn summarize_token(&self, token: u32) -> AttributeSummary {
        AttributeSummary::from_attrs(token, self.registry.for_token(token))
    }

    pub fn filter(&self, filter: &AttributeFilter) -> Vec<(u32, &DecodedAttribute)> {
        self.registry.by_target_token.iter()
            .flat_map(|(tok, attrs)| attrs.iter().map(move |a| (*tok, a)))
            .filter(|(_, a)| filter.matches(a))
            .collect()
    }
}

impl Default for BulkAttributeReader {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_ctor(token: u32, type_name: &str, params: Vec<CtorParam>) -> AttributeCtorDescriptor {
        AttributeCtorDescriptor { token, declaring_type: type_name.to_string(), params }
    }

    fn _encode_test_blob(args: &[&[u8]]) -> Vec<u8> {
        let mut blob = vec![0x01, 0x00]; // prolog
        for a in args { blob.extend_from_slice(a); }
        blob.extend_from_slice(&[0x00, 0x00]); // 0 named args
        blob
    }

    #[test]
    fn test_decode_bool_positional() {
        let ctor = make_test_ctor(0x06000001, "System.ObsoleteAttribute", vec![
            CtorParam { name: "message".into(), param_type: FixedArgType::String },
            CtorParam { name: "error".into(), param_type: FixedArgType::Bool },
        ]);
        // "hello" as ser_string + true as bool
        let mut blob = vec![0x01, 0x00];
        blob.push(5); // string len
        blob.extend_from_slice(b"hello");
        blob.push(1); // true
        blob.extend_from_slice(&[0x00, 0x00]); // 0 named args
        let mut reader = AttributeBlobReader::new(&blob);
        let decoded = reader.decode_attribute(&ctor).unwrap();
        assert_eq!(decoded.positional_args.len(), 2);
        assert_eq!(decoded.positional_as_string(0), Some("hello"));
        assert_eq!(decoded.positional_as_bool(1), Some(true));
    }

    #[test]
    fn test_decode_i4_positional() {
        let ctor = make_test_ctor(0x06000002, "System.Runtime.InteropServices.StructLayoutAttribute", vec![
            CtorParam { name: "layoutKind".into(), param_type: FixedArgType::I4 },
        ]);
        let mut blob = vec![0x01, 0x00];
        blob.extend_from_slice(&2i32.to_le_bytes()); // Sequential = 0, Explicit = 2
        blob.extend_from_slice(&[0x00, 0x00]);
        let mut reader = AttributeBlobReader::new(&blob);
        let decoded = reader.decode_attribute(&ctor).unwrap();
        assert_eq!(decoded.positional_as_i32(0), Some(2));
    }

    #[test]
    fn test_decode_named_property() {
        let ctor = make_test_ctor(0x06000003, "System.Runtime.InteropServices.DllImportAttribute", vec![
            CtorParam { name: "dllName".into(), param_type: FixedArgType::String },
        ]);
        let dll_name = b"kernel32.dll";
        let entry_point = b"CreateFileW";
        let mut blob = vec![0x01, 0x00];
        blob.push(dll_name.len() as u8);
        blob.extend_from_slice(dll_name);
        // 1 named property
        blob.extend_from_slice(&[0x01, 0x00]);
        blob.push(0x54); // property
        blob.push(0x0E); // String type
        blob.push(entry_point.len() as u8);
        blob.extend_from_slice(entry_point);
        blob.push(entry_point.len() as u8);
        blob.extend_from_slice(entry_point);
        let mut reader = AttributeBlobReader::new(&blob);
        let decoded = reader.decode_attribute(&ctor).unwrap();
        assert_eq!(decoded.positional_as_string(0), Some("kernel32.dll"));
        assert_eq!(decoded.named_args.len(), 1);
    }

    #[test]
    fn test_ser_string_null() {
        let mut reader = AttributeBlobReader::new(&[0xFF]);
        let s = reader.read_ser_string().unwrap();
        assert!(s.is_none());
    }

    #[test]
    fn test_attribute_registry_lookup() {
        let mut reg = AttributeRegistry::new();
        reg.add_decoded(0x02000001, DecodedAttribute {
            attribute_type: "System.SerializableAttribute".into(),
            constructor_token: 0,
            positional_args: vec![],
            named_args: vec![],
            raw_blob_offset: 0,
            raw_blob_len: 4,
        });
        let attrs = reg.for_token(0x02000001);
        assert_eq!(attrs.len(), 1);
        assert!(well_known::is_serializable(&attrs[0]));
    }

    #[test]
    fn test_well_known_predicates() {
        let attr = DecodedAttribute {
            attribute_type: "System.FlagsAttribute".into(),
            constructor_token: 0,
            positional_args: vec![],
            named_args: vec![],
            raw_blob_offset: 0,
            raw_blob_len: 4,
        };
        assert!(well_known::is_flags_enum(&attr));
        assert!(!well_known::is_obsolete(&attr));
    }

    #[test]
    fn test_attribute_filter() {
        let attr = DecodedAttribute {
            attribute_type: "System.ObsoleteAttribute".into(),
            constructor_token: 0,
            positional_args: vec![FixedArg::String(Some("Use Foo instead".into()))],
            named_args: vec![],
            raw_blob_offset: 0,
            raw_blob_len: 20,
        };
        let filter = AttributeFilter::new().with_type_contains("Obsolete").with_positional_count(1);
        assert!(filter.matches(&attr));
        let filter2 = AttributeFilter::new().with_positional_count(2);
        assert!(!filter2.matches(&attr));
    }
}
