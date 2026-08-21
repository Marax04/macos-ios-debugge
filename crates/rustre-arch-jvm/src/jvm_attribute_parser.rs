//! `jvm_attribute_parser` — parse JVM `.class` attribute structures.
//!
//! Implements parsing for the most important JVM §4.7 attributes:
//! `Code`, `ConstantValue`, `Exceptions`, `LineNumberTable`,
//! `LocalVariableTable`, `SourceFile`, `Deprecated`, `Synthetic`,
//! `Signature`, `InnerClasses`, `EnclosingMethod`, `BootstrapMethods`,
//! `MethodParameters`, `StackMapTable`, and `RuntimeVisibleAnnotations`.
//!
//! The entry point is [`JvmAttributeParser::parse_all`], which decodes an
//! array of `{u16 name_index, u32 length, u8[length] info}` records and
//! returns a `Vec<JvmAttribute>`.

use std::fmt;

// ── Error ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttrParseError {
    Truncated { attr: String, at: usize },
    UnknownAttribute(String),
    InvalidUtf8Index(u16),
    InvalidIndex { index: u16 },
    BadMagic { expected: u8, got: u8 },
}

impl fmt::Display for AttrParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated { attr, at } => write!(f, "attribute `{attr}` truncated at byte {at}"),
            Self::UnknownAttribute(n) => write!(f, "unknown attribute `{n}`"),
            Self::InvalidUtf8Index(i) => write!(f, "invalid UTF-8 cp index #{i}"),
            Self::InvalidIndex { index } => write!(f, "invalid cp index #{index}"),
            Self::BadMagic { expected, got } => write!(f, "bad tag byte: expected 0x{expected:02x} got 0x{got:02x}"),
        }
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn read_u8(buf: &[u8], pos: &mut usize, attr: &str) -> Result<u8, AttrParseError> {
    if *pos >= buf.len() {
        return Err(AttrParseError::Truncated { attr: attr.to_owned(), at: *pos });
    }
    let v = buf[*pos];
    *pos += 1;
    Ok(v)
}

fn read_u16(buf: &[u8], pos: &mut usize, attr: &str) -> Result<u16, AttrParseError> {
    if *pos + 2 > buf.len() {
        return Err(AttrParseError::Truncated { attr: attr.to_owned(), at: *pos });
    }
    let v = u16::from_be_bytes([buf[*pos], buf[*pos + 1]]);
    *pos += 2;
    Ok(v)
}

fn read_u32(buf: &[u8], pos: &mut usize, attr: &str) -> Result<u32, AttrParseError> {
    if *pos + 4 > buf.len() {
        return Err(AttrParseError::Truncated { attr: attr.to_owned(), at: *pos });
    }
    let v = u32::from_be_bytes([buf[*pos], buf[*pos+1], buf[*pos+2], buf[*pos+3]]);
    *pos += 4;
    Ok(v)
}

fn read_i16(buf: &[u8], pos: &mut usize, attr: &str) -> Result<i16, AttrParseError> {
    read_u16(buf, pos, attr).map(u16::cast_signed)
}

fn read_bytes<'a>(buf: &'a [u8], pos: &mut usize, len: usize, attr: &str) -> Result<&'a [u8], AttrParseError> {
    if *pos + len > buf.len() {
        return Err(AttrParseError::Truncated { attr: attr.to_owned(), at: *pos });
    }
    let slice = &buf[*pos..*pos + len];
    *pos += len;
    Ok(slice)
}

// ── Sub-types ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExceptionTableEntry {
    pub start_pc: u16,
    pub end_pc: u16,
    pub handler_pc: u16,
    /// `0` means catch all.
    pub catch_type: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LineNumberEntry {
    pub start_pc: u16,
    pub line_number: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalVariableEntry {
    pub start_pc: u16,
    pub length: u16,
    pub name_index: u16,
    pub descriptor_index: u16,
    pub index: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalVariableTypeEntry {
    pub start_pc: u16,
    pub length: u16,
    pub name_index: u16,
    pub signature_index: u16,
    pub index: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InnerClassEntry {
    pub inner_class_info_index: u16,
    pub outer_class_info_index: u16,
    pub inner_name_index: u16,
    pub inner_class_access_flags: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootstrapMethodEntry {
    pub bootstrap_method_ref: u16,
    pub arguments: Vec<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MethodParameter {
    pub name_index: u16,
    pub access_flags: u16,
}

/// A single element-value pair in an annotation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElementValuePair {
    pub element_name_index: u16,
    pub tag: u8,
    pub const_value_index: Option<u16>,
}

/// Parsed annotation entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Annotation {
    pub type_index: u16,
    pub element_value_pairs: Vec<ElementValuePair>,
}

/// Verification type for `StackMapTable`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerificationTypeInfo {
    Top,
    Integer,
    Float,
    Long,
    Double,
    Null,
    UninitializedThis,
    Object(u16),
    Uninitialized(u16),
}

impl VerificationTypeInfo {
    fn parse(buf: &[u8], pos: &mut usize) -> Result<Self, AttrParseError> {
        let tag = read_u8(buf, pos, "StackMapTable")?;
        Ok(match tag {
            0 => Self::Top,
            1 => Self::Integer,
            2 => Self::Float,
            4 => Self::Long,
            3 => Self::Double,
            5 => Self::Null,
            6 => Self::UninitializedThis,
            7 => { let i = read_u16(buf, pos, "StackMapTable")?; Self::Object(i) }
            8 => { let o = read_u16(buf, pos, "StackMapTable")?; Self::Uninitialized(o) }
            _ => return Err(AttrParseError::BadMagic { expected: 0, got: tag }),
        })
    }
}

/// A stack map frame entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StackMapFrame {
    pub frame_type: u8,
    pub locals: Vec<VerificationTypeInfo>,
    pub stack: Vec<VerificationTypeInfo>,
}

impl StackMapFrame {
    fn parse(buf: &[u8], pos: &mut usize) -> Result<Self, AttrParseError> {
        let frame_type = read_u8(buf, pos, "StackMapTable")?;
        match frame_type {
            // 0..=63 (same_frame) carries no extra data, exactly like the
            // reserved/unknown frame types handled by the final arm.
            64..=127 => {
                let vti = VerificationTypeInfo::parse(buf, pos)?;
                Ok(Self { frame_type, locals: vec![], stack: vec![vti] })
            }
            247 => {
                let _offset_delta = read_u16(buf, pos, "StackMapTable")?;
                let vti = VerificationTypeInfo::parse(buf, pos)?;
                Ok(Self { frame_type, locals: vec![], stack: vec![vti] })
            }
            // 248..=250 (chop_frame) and 251 (same_frame_extended) both carry
            // only an offset_delta and describe no locals or stack entries.
            248..=251 => {
                let _offset_delta = read_u16(buf, pos, "StackMapTable")?;
                Ok(Self { frame_type, locals: vec![], stack: vec![] })
            }
            252..=254 => {
                let _offset_delta = read_u16(buf, pos, "StackMapTable")?;
                let n = (frame_type - 251) as usize;
                // n is at most 3 (frame_type 252–254), no cap needed.
                let mut locals = Vec::with_capacity(n);
                for _ in 0..n {
                    locals.push(VerificationTypeInfo::parse(buf, pos)?);
                }
                Ok(Self { frame_type, locals, stack: vec![] })
            }
            255 => {
                let _offset_delta = read_u16(buf, pos, "StackMapTable")?;
                let nl = read_u16(buf, pos, "StackMapTable")? as usize;
                // Cap to remaining buffer (each verification type is at least 1 byte).
                let nl_cap = nl.min(buf.len().saturating_sub(*pos));
                let mut locals = Vec::with_capacity(nl_cap);
                for _ in 0..nl {
                    locals.push(VerificationTypeInfo::parse(buf, pos)?);
                }
                let ns = read_u16(buf, pos, "StackMapTable")? as usize;
                let ns_cap = ns.min(buf.len().saturating_sub(*pos));
                let mut stack = Vec::with_capacity(ns_cap);
                for _ in 0..ns {
                    stack.push(VerificationTypeInfo::parse(buf, pos)?);
                }
                Ok(Self { frame_type, locals, stack })
            }
            // same_frame (0..=63) plus reserved / unrecognised frame types.
            _ => Ok(Self { frame_type, locals: vec![], stack: vec![] }),
        }
    }
}

// ── CodeAttribute ─────────────────────────────────────────────────────────────

/// Decoded `Code` attribute.
#[derive(Debug, Clone, PartialEq)]
pub struct CodeAttribute {
    pub max_stack: u16,
    pub max_locals: u16,
    pub bytecode: Vec<u8>,
    pub exception_table: Vec<ExceptionTableEntry>,
    pub inner_attributes: Vec<JvmAttribute>,
}

// ── JvmAttribute ─────────────────────────────────────────────────────────────

/// All supported JVM attribute variants.
#[derive(Debug, Clone, PartialEq)]
pub enum JvmAttribute {
    ConstantValue(u16),
    Code(CodeAttribute),
    Exceptions(Vec<u16>),
    SourceFile(u16),
    LineNumberTable(Vec<LineNumberEntry>),
    LocalVariableTable(Vec<LocalVariableEntry>),
    LocalVariableTypeTable(Vec<LocalVariableTypeEntry>),
    Deprecated,
    Synthetic,
    Signature(u16),
    InnerClasses(Vec<InnerClassEntry>),
    EnclosingMethod { class_index: u16, method_index: u16 },
    BootstrapMethods(Vec<BootstrapMethodEntry>),
    MethodParameters(Vec<MethodParameter>),
    StackMapTable(Vec<StackMapFrame>),
    RuntimeVisibleAnnotations(Vec<Annotation>),
    /// Raw bytes for unrecognised attributes.
    Unknown { name: String, bytes: Vec<u8> },
}

impl JvmAttribute {
    #[must_use] 
    pub const fn name(&self) -> &str {
        match self {
            Self::ConstantValue(_) => "ConstantValue",
            Self::Code(_) => "Code",
            Self::Exceptions(_) => "Exceptions",
            Self::SourceFile(_) => "SourceFile",
            Self::LineNumberTable(_) => "LineNumberTable",
            Self::LocalVariableTable(_) => "LocalVariableTable",
            Self::LocalVariableTypeTable(_) => "LocalVariableTypeTable",
            Self::Deprecated => "Deprecated",
            Self::Synthetic => "Synthetic",
            Self::Signature(_) => "Signature",
            Self::InnerClasses(_) => "InnerClasses",
            Self::EnclosingMethod { .. } => "EnclosingMethod",
            Self::BootstrapMethods(_) => "BootstrapMethods",
            Self::MethodParameters(_) => "MethodParameters",
            Self::StackMapTable(_) => "StackMapTable",
            Self::RuntimeVisibleAnnotations(_) => "RuntimeVisibleAnnotations",
            Self::Unknown { name, .. } => name.as_str(),
        }
    }
}

// ── JvmAttributeParser ────────────────────────────────────────────────────────

/// Stateless attribute parser.  Call [`parse_all`] with:
/// - `buf`   — the raw bytes of the attributes region
/// - `count` — the `attributes_count` field value
/// - `cp_utf8` — a callback `Fn(u16) -> Option<&str>` to resolve Utf8 cp entries
pub struct JvmAttributeParser;

impl JvmAttributeParser {
    /// Parse `count` attributes from `buf`.
    ///
    /// The `cp_utf8` closure resolves a constant-pool index to a `&str`.
    /// Any attribute whose name cannot be resolved is stored as `Unknown`.
    pub fn parse_all<'a, F>(
        buf: &[u8],
        count: u16,
        cp_utf8: F,
    ) -> Result<Vec<JvmAttribute>, AttrParseError>
    where
        F: Fn(u16) -> Option<&'a str>,
    {
        Self::parse_all_ref(buf, count, &cp_utf8)
    }

    /// Same as [`parse_all`] but takes the resolver by reference, so recursive
    /// calls inside `Code` attributes don't re-monomorphize the parser with an
    /// ever-deepening `&&...&F` type.
    pub fn parse_all_ref<'a, F>(
        buf: &[u8],
        count: u16,
        cp_utf8: &F,
    ) -> Result<Vec<JvmAttribute>, AttrParseError>
    where
        F: Fn(u16) -> Option<&'a str>,
    {
        let mut pos = 0;
        // Cap pre-allocation: each attribute is at minimum 6 bytes (u16 name + u32 length).
        let cap = (count as usize).min(buf.len() / 6);
        let mut attrs = Vec::with_capacity(cap);

        for _ in 0..count {
            let name_index = read_u16(buf, &mut pos, "attribute header")?;
            let length = read_u32(buf, &mut pos, "attribute header")? as usize;

            if pos + length > buf.len() {
                return Err(AttrParseError::Truncated {
                    attr: format!("#{name_index}"),
                    at: pos,
                });
            }
            let info = &buf[pos..pos + length];
            pos += length;

            let name = cp_utf8(name_index).unwrap_or("").to_owned();
            let attr = Self::parse_one(&name, info, cp_utf8)?;
            attrs.push(attr);
        }
        Ok(attrs)
    }

    /// Parse a single attribute given its resolved `name` and raw `info` bytes.
    pub fn parse_one<'a, F>(
        name: &str,
        info: &[u8],
        cp_utf8: &F,
    ) -> Result<JvmAttribute, AttrParseError>
    where
        F: Fn(u16) -> Option<&'a str>,
    {
        match name {
            "ConstantValue" => Self::parse_constant_value(info),
            "Code" => Self::parse_code(info, cp_utf8),
            "Exceptions" => Self::parse_exceptions(info),
            "SourceFile" => Self::parse_source_file(info),
            "LineNumberTable" => Self::parse_line_number_table(info),
            "LocalVariableTable" => Self::parse_local_variable_table(info),
            "LocalVariableTypeTable" => Self::parse_local_variable_type_table(info),
            "Deprecated" => Ok(JvmAttribute::Deprecated),
            "Synthetic" => Ok(JvmAttribute::Synthetic),
            "Signature" => Self::parse_signature(info),
            "InnerClasses" => Self::parse_inner_classes(info),
            "EnclosingMethod" => Self::parse_enclosing_method(info),
            "BootstrapMethods" => Self::parse_bootstrap_methods(info),
            "MethodParameters" => Self::parse_method_parameters(info),
            "StackMapTable" => Self::parse_stack_map_table(info),
            "RuntimeVisibleAnnotations" => Self::parse_runtime_visible_annotations(info),
            _ => Ok(JvmAttribute::Unknown { name: name.to_owned(), bytes: info.to_vec() }),
        }
    }

    /// Read a big-endian signed 16-bit value from `info` at offset `pos`,
    /// advancing `pos` by 2 bytes.
    ///
    /// Exposed for external decoders that need to read JVMS-signed shorts
    /// (e.g. branch offsets in bytecode, or signed constant-pool values
    /// referenced from custom attributes).
    ///
    /// # Errors
    /// Returns [`AttrParseError::Truncated`] when fewer than 2 bytes remain.
    pub fn read_signed_short(
        info: &[u8],
        pos: &mut usize,
        attr_name: &str,
    ) -> Result<i16, AttrParseError> {
        read_i16(info, pos, attr_name)
    }

    fn parse_constant_value(info: &[u8]) -> Result<JvmAttribute, AttrParseError> {
        let mut pos = 0;
        let idx = read_u16(info, &mut pos, "ConstantValue")?;
        Ok(JvmAttribute::ConstantValue(idx))
    }

    fn parse_source_file(info: &[u8]) -> Result<JvmAttribute, AttrParseError> {
        let mut pos = 0;
        let idx = read_u16(info, &mut pos, "SourceFile")?;
        Ok(JvmAttribute::SourceFile(idx))
    }

    fn parse_signature(info: &[u8]) -> Result<JvmAttribute, AttrParseError> {
        let mut pos = 0;
        let idx = read_u16(info, &mut pos, "Signature")?;
        Ok(JvmAttribute::Signature(idx))
    }

    fn parse_exceptions(info: &[u8]) -> Result<JvmAttribute, AttrParseError> {
        let mut pos = 0;
        let n = read_u16(info, &mut pos, "Exceptions")? as usize;
        // Cap pre-allocation: each entry is 2 bytes; guard against inflated count.
        let cap = n.min((info.len().saturating_sub(pos)) / 2);
        let mut table = Vec::with_capacity(cap);
        for _ in 0..n {
            table.push(read_u16(info, &mut pos, "Exceptions")?);
        }
        Ok(JvmAttribute::Exceptions(table))
    }

    fn parse_line_number_table(info: &[u8]) -> Result<JvmAttribute, AttrParseError> {
        let mut pos = 0;
        let n = read_u16(info, &mut pos, "LineNumberTable")? as usize;
        // Cap pre-allocation: each entry is 4 bytes (start_pc u16 + line_number u16).
        let cap = n.min((info.len().saturating_sub(pos)) / 4);
        let mut table = Vec::with_capacity(cap);
        for _ in 0..n {
            let start_pc = read_u16(info, &mut pos, "LineNumberTable")?;
            let line_number = read_u16(info, &mut pos, "LineNumberTable")?;
            table.push(LineNumberEntry { start_pc, line_number });
        }
        Ok(JvmAttribute::LineNumberTable(table))
    }

    fn parse_local_variable_table(info: &[u8]) -> Result<JvmAttribute, AttrParseError> {
        let mut pos = 0;
        let n = read_u16(info, &mut pos, "LocalVariableTable")? as usize;
        // Cap pre-allocation: each entry is 10 bytes (5 x u16).
        let cap = n.min((info.len().saturating_sub(pos)) / 10);
        let mut table = Vec::with_capacity(cap);
        for _ in 0..n {
            let start_pc = read_u16(info, &mut pos, "LocalVariableTable")?;
            let length = read_u16(info, &mut pos, "LocalVariableTable")?;
            let name_index = read_u16(info, &mut pos, "LocalVariableTable")?;
            let descriptor_index = read_u16(info, &mut pos, "LocalVariableTable")?;
            let index = read_u16(info, &mut pos, "LocalVariableTable")?;
            table.push(LocalVariableEntry { start_pc, length, name_index, descriptor_index, index });
        }
        Ok(JvmAttribute::LocalVariableTable(table))
    }

    fn parse_local_variable_type_table(info: &[u8]) -> Result<JvmAttribute, AttrParseError> {
        let mut pos = 0;
        let n = read_u16(info, &mut pos, "LocalVariableTypeTable")? as usize;
        // Cap pre-allocation: each entry is 10 bytes (5 x u16).
        let cap = n.min((info.len().saturating_sub(pos)) / 10);
        let mut table = Vec::with_capacity(cap);
        for _ in 0..n {
            let start_pc = read_u16(info, &mut pos, "LocalVariableTypeTable")?;
            let length = read_u16(info, &mut pos, "LocalVariableTypeTable")?;
            let name_index = read_u16(info, &mut pos, "LocalVariableTypeTable")?;
            let signature_index = read_u16(info, &mut pos, "LocalVariableTypeTable")?;
            let index = read_u16(info, &mut pos, "LocalVariableTypeTable")?;
            table.push(LocalVariableTypeEntry { start_pc, length, name_index, signature_index, index });
        }
        Ok(JvmAttribute::LocalVariableTypeTable(table))
    }

    fn parse_inner_classes(info: &[u8]) -> Result<JvmAttribute, AttrParseError> {
        let mut pos = 0;
        let n = read_u16(info, &mut pos, "InnerClasses")? as usize;
        // Cap pre-allocation: each entry is 8 bytes (4 x u16).
        let cap = n.min((info.len().saturating_sub(pos)) / 8);
        let mut table = Vec::with_capacity(cap);
        for _ in 0..n {
            let inner_class_info_index = read_u16(info, &mut pos, "InnerClasses")?;
            let outer_class_info_index = read_u16(info, &mut pos, "InnerClasses")?;
            let inner_name_index = read_u16(info, &mut pos, "InnerClasses")?;
            let inner_class_access_flags = read_u16(info, &mut pos, "InnerClasses")?;
            table.push(InnerClassEntry { inner_class_info_index, outer_class_info_index, inner_name_index, inner_class_access_flags });
        }
        Ok(JvmAttribute::InnerClasses(table))
    }

    fn parse_enclosing_method(info: &[u8]) -> Result<JvmAttribute, AttrParseError> {
        let mut pos = 0;
        let class_index = read_u16(info, &mut pos, "EnclosingMethod")?;
        let method_index = read_u16(info, &mut pos, "EnclosingMethod")?;
        Ok(JvmAttribute::EnclosingMethod { class_index, method_index })
    }

    fn parse_bootstrap_methods(info: &[u8]) -> Result<JvmAttribute, AttrParseError> {
        let mut pos = 0;
        let n = read_u16(info, &mut pos, "BootstrapMethods")? as usize;
        // Cap pre-allocation: minimum 4 bytes per bootstrap method entry.
        let cap = n.min((info.len().saturating_sub(pos)) / 4);
        let mut methods = Vec::with_capacity(cap);
        for _ in 0..n {
            let bootstrap_method_ref = read_u16(info, &mut pos, "BootstrapMethods")?;
            let na = read_u16(info, &mut pos, "BootstrapMethods")? as usize;
            // Cap arg pre-allocation to remaining buffer (each arg is 2 bytes).
            let arg_cap = na.min((info.len().saturating_sub(pos)) / 2);
            let mut args = Vec::with_capacity(arg_cap);
            for _ in 0..na {
                args.push(read_u16(info, &mut pos, "BootstrapMethods")?);
            }
            methods.push(BootstrapMethodEntry { bootstrap_method_ref, arguments: args });
        }
        Ok(JvmAttribute::BootstrapMethods(methods))
    }

    fn parse_method_parameters(info: &[u8]) -> Result<JvmAttribute, AttrParseError> {
        let mut pos = 0;
        let n = read_u8(info, &mut pos, "MethodParameters")? as usize;
        let mut params = Vec::with_capacity(n);
        for _ in 0..n {
            let name_index = read_u16(info, &mut pos, "MethodParameters")?;
            let access_flags = read_u16(info, &mut pos, "MethodParameters")?;
            params.push(MethodParameter { name_index, access_flags });
        }
        Ok(JvmAttribute::MethodParameters(params))
    }

    fn parse_stack_map_table(info: &[u8]) -> Result<JvmAttribute, AttrParseError> {
        let mut pos = 0;
        let n = read_u16(info, &mut pos, "StackMapTable")? as usize;
        // Cap pre-allocation: each frame is at minimum 1 byte (frame_type).
        let cap = n.min(info.len().saturating_sub(pos));
        let mut frames = Vec::with_capacity(cap);
        for _ in 0..n {
            frames.push(StackMapFrame::parse(info, &mut pos)?);
        }
        Ok(JvmAttribute::StackMapTable(frames))
    }

    fn parse_runtime_visible_annotations(info: &[u8]) -> Result<JvmAttribute, AttrParseError> {
        let mut pos = 0;
        let n = read_u16(info, &mut pos, "RuntimeVisibleAnnotations")? as usize;
        // Cap pre-allocation: each annotation is at minimum 4 bytes.
        let cap = n.min((info.len().saturating_sub(pos)) / 4);
        let mut annotations = Vec::with_capacity(cap);
        for _ in 0..n {
            annotations.push(Self::parse_annotation(info, &mut pos)?);
        }
        Ok(JvmAttribute::RuntimeVisibleAnnotations(annotations))
    }

    fn parse_annotation(info: &[u8], pos: &mut usize) -> Result<Annotation, AttrParseError> {
        let type_index = read_u16(info, pos, "Annotation")?;
        let n = read_u16(info, pos, "Annotation")? as usize;
        let mut pairs = Vec::with_capacity(n);
        for _ in 0..n {
            let element_name_index = read_u16(info, pos, "Annotation")?;
            let tag = read_u8(info, pos, "Annotation")?;
            let const_value_index = match tag {
                b'B' | b'C' | b'D' | b'F' | b'I' | b'J' | b'S' | b'Z' | b's' => {
                    Some(read_u16(info, pos, "Annotation")?)
                }
                b'e' => {
                    let _type_name = read_u16(info, pos, "Annotation")?;
                    Some(read_u16(info, pos, "Annotation")?)
                }
                b'c' => Some(read_u16(info, pos, "Annotation")?),
                _ => None,
            };
            pairs.push(ElementValuePair { element_name_index, tag, const_value_index });
        }
        Ok(Annotation { type_index, element_value_pairs: pairs })
    }

    /// Parse the `Code` attribute including its nested sub-attributes.
    pub fn parse_code<'a, F>(info: &[u8], cp_utf8: &F) -> Result<JvmAttribute, AttrParseError>
    where
        F: Fn(u16) -> Option<&'a str>,
    {
        parse_code_attr(info, cp_utf8).map(JvmAttribute::Code)
    }
}

/// Parse a `Code` attribute body, returning a [`CodeAttribute`].
pub fn parse_code_attr<'a, F>(info: &[u8], cp_utf8: &F) -> Result<CodeAttribute, AttrParseError>
where
    F: Fn(u16) -> Option<&'a str>,
{
    let mut pos = 0;
    let max_stack = read_u16(info, &mut pos, "Code")?;
    let max_locals = read_u16(info, &mut pos, "Code")?;
    let code_length = read_u32(info, &mut pos, "Code")? as usize;
    let bytecode = read_bytes(info, &mut pos, code_length, "Code")?.to_vec();
    let ex_count = read_u16(info, &mut pos, "Code")? as usize;
    // Cap pre-allocation: each exception table entry is 8 bytes (4 x u16).
    let ex_cap = ex_count.min((info.len().saturating_sub(pos)) / 8);
    let mut exception_table = Vec::with_capacity(ex_cap);
    for _ in 0..ex_count {
        let start_pc = read_u16(info, &mut pos, "Code")?;
        let end_pc = read_u16(info, &mut pos, "Code")?;
        let handler_pc = read_u16(info, &mut pos, "Code")?;
        let catch_type = read_u16(info, &mut pos, "Code")?;
        exception_table.push(ExceptionTableEntry { start_pc, end_pc, handler_pc, catch_type });
    }
    let attr_count = read_u16(info, &mut pos, "Code")?;
    let inner_attributes = JvmAttributeParser::parse_all_ref(&info[pos..], attr_count, cp_utf8)?;
    Ok(CodeAttribute { max_stack, max_locals, bytecode, exception_table, inner_attributes })
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn no_cp(_: u16) -> Option<&'static str> { None }

    fn cp_with(entries: &'static [(u16, &'static str)]) -> impl Fn(u16) -> Option<&'static str> {
        move |idx| entries.iter().find(|(i, _)| *i == idx).map(|(_, s)| *s)
    }

    // ── ConstantValue ─────────────────────────────────────────────────────────

    #[test]
    fn parse_constant_value_attr() {
        let info = 5u16.to_be_bytes().to_vec();
        let attr = JvmAttributeParser::parse_one("ConstantValue", &info, &no_cp).unwrap();
        assert_eq!(attr, JvmAttribute::ConstantValue(5));
    }

    // ── SourceFile ────────────────────────────────────────────────────────────

    #[test]
    fn parse_source_file_attr() {
        let info = 7u16.to_be_bytes().to_vec();
        let attr = JvmAttributeParser::parse_one("SourceFile", &info, &no_cp).unwrap();
        assert_eq!(attr, JvmAttribute::SourceFile(7));
    }

    // ── Deprecated / Synthetic ────────────────────────────────────────────────

    #[test]
    fn parse_deprecated() {
        let attr = JvmAttributeParser::parse_one("Deprecated", &[], &no_cp).unwrap();
        assert_eq!(attr, JvmAttribute::Deprecated);
    }

    #[test]
    fn parse_synthetic() {
        let attr = JvmAttributeParser::parse_one("Synthetic", &[], &no_cp).unwrap();
        assert_eq!(attr, JvmAttribute::Synthetic);
    }

    // ── Exceptions ────────────────────────────────────────────────────────────

    #[test]
    fn parse_exceptions_attr() {
        let mut v = Vec::new();
        v.extend_from_slice(&2u16.to_be_bytes());
        v.extend_from_slice(&3u16.to_be_bytes());
        v.extend_from_slice(&4u16.to_be_bytes());
        let attr = JvmAttributeParser::parse_one("Exceptions", &v, &no_cp).unwrap();
        assert_eq!(attr, JvmAttribute::Exceptions(vec![3, 4]));
    }

    // ── LineNumberTable ───────────────────────────────────────────────────────

    #[test]
    fn parse_line_number_table_attr() {
        let mut v = Vec::new();
        v.extend_from_slice(&1u16.to_be_bytes()); // count
        v.extend_from_slice(&0u16.to_be_bytes()); // start_pc
        v.extend_from_slice(&10u16.to_be_bytes()); // line_number
        let attr = JvmAttributeParser::parse_one("LineNumberTable", &v, &no_cp).unwrap();
        assert_eq!(attr, JvmAttribute::LineNumberTable(vec![LineNumberEntry { start_pc: 0, line_number: 10 }]));
    }

    // ── LocalVariableTable ────────────────────────────────────────────────────

    #[test]
    fn parse_local_variable_table_attr() {
        let mut v = Vec::new();
        v.extend_from_slice(&1u16.to_be_bytes()); // count
        for val in [0u16, 20, 1, 2, 0] {
            v.extend_from_slice(&val.to_be_bytes());
        }
        let attr = JvmAttributeParser::parse_one("LocalVariableTable", &v, &no_cp).unwrap();
        if let JvmAttribute::LocalVariableTable(entries) = attr {
            assert_eq!(entries.len(), 1);
            assert_eq!(entries[0].name_index, 1);
        } else {
            panic!("wrong variant");
        }
    }

    // ── InnerClasses ──────────────────────────────────────────────────────────

    #[test]
    fn parse_inner_classes_attr() {
        let mut v = Vec::new();
        v.extend_from_slice(&1u16.to_be_bytes()); // count
        for val in [5u16, 6, 7, 0] {
            v.extend_from_slice(&val.to_be_bytes());
        }
        let attr = JvmAttributeParser::parse_one("InnerClasses", &v, &no_cp).unwrap();
        if let JvmAttribute::InnerClasses(entries) = attr {
            assert_eq!(entries[0].inner_class_info_index, 5);
        } else {
            panic!("wrong variant");
        }
    }

    // ── EnclosingMethod ───────────────────────────────────────────────────────

    #[test]
    fn parse_enclosing_method_attr() {
        let mut v = Vec::new();
        v.extend_from_slice(&3u16.to_be_bytes());
        v.extend_from_slice(&4u16.to_be_bytes());
        let attr = JvmAttributeParser::parse_one("EnclosingMethod", &v, &no_cp).unwrap();
        assert_eq!(attr, JvmAttribute::EnclosingMethod { class_index: 3, method_index: 4 });
    }

    // ── BootstrapMethods ──────────────────────────────────────────────────────

    #[test]
    fn parse_bootstrap_methods_attr() {
        let mut v = Vec::new();
        v.extend_from_slice(&1u16.to_be_bytes()); // num_bootstrap_methods
        v.extend_from_slice(&10u16.to_be_bytes()); // bootstrap_method_ref
        v.extend_from_slice(&2u16.to_be_bytes()); // num_bootstrap_arguments
        v.extend_from_slice(&11u16.to_be_bytes());
        v.extend_from_slice(&12u16.to_be_bytes());
        let attr = JvmAttributeParser::parse_one("BootstrapMethods", &v, &no_cp).unwrap();
        if let JvmAttribute::BootstrapMethods(methods) = attr {
            assert_eq!(methods[0].bootstrap_method_ref, 10);
            assert_eq!(methods[0].arguments, vec![11, 12]);
        } else {
            panic!("wrong variant");
        }
    }

    // ── MethodParameters ──────────────────────────────────────────────────────

    #[test]
    fn parse_method_parameters_attr() {
        let mut v = Vec::new();
        v.push(1u8); // parameters_count (u8, not u16!)
        v.extend_from_slice(&5u16.to_be_bytes()); // name_index
        v.extend_from_slice(&0u16.to_be_bytes()); // access_flags
        let attr = JvmAttributeParser::parse_one("MethodParameters", &v, &no_cp).unwrap();
        if let JvmAttribute::MethodParameters(params) = attr {
            assert_eq!(params[0].name_index, 5);
        } else {
            panic!("wrong variant");
        }
    }

    // ── Unknown ───────────────────────────────────────────────────────────────

    #[test]
    fn unknown_attribute_stored_as_raw() {
        let info = vec![0xDEu8, 0xAD, 0xBE, 0xEF];
        let attr = JvmAttributeParser::parse_one("MyCustomAttr", &info, &no_cp).unwrap();
        if let JvmAttribute::Unknown { name, bytes } = attr {
            assert_eq!(name, "MyCustomAttr");
            assert_eq!(bytes, info);
        } else {
            panic!("expected Unknown");
        }
    }

    // ── Code attribute ────────────────────────────────────────────────────────

    #[test]
    fn parse_code_attr_minimal() {
        let mut v = Vec::new();
        v.extend_from_slice(&4u16.to_be_bytes()); // max_stack
        v.extend_from_slice(&2u16.to_be_bytes()); // max_locals
        v.extend_from_slice(&3u32.to_be_bytes()); // code_length
        v.extend_from_slice(&[0xB1u8, 0x00, 0x00]); // return; nop; nop
        v.extend_from_slice(&0u16.to_be_bytes()); // exception_table_length = 0
        v.extend_from_slice(&0u16.to_be_bytes()); // attributes_count = 0
        let ca = parse_code_attr(&v, &no_cp).unwrap();
        assert_eq!(ca.max_stack, 4);
        assert_eq!(ca.max_locals, 2);
        assert_eq!(ca.bytecode, vec![0xB1, 0x00, 0x00]);
        assert!(ca.exception_table.is_empty());
    }

    // ── parse_all ─────────────────────────────────────────────────────────────

    #[test]
    fn parse_all_with_cp_resolver() {
        let cp = cp_with(&[(1, "Deprecated"), (2, "Synthetic")]);

        let mut buf = Vec::new();
        // attr 1: Deprecated (name_index=1, length=0)
        buf.extend_from_slice(&1u16.to_be_bytes());
        buf.extend_from_slice(&0u32.to_be_bytes());
        // attr 2: Synthetic (name_index=2, length=0)
        buf.extend_from_slice(&2u16.to_be_bytes());
        buf.extend_from_slice(&0u32.to_be_bytes());

        let attrs = JvmAttributeParser::parse_all(&buf, 2, cp).unwrap();
        assert_eq!(attrs.len(), 2);
        assert_eq!(attrs[0], JvmAttribute::Deprecated);
        assert_eq!(attrs[1], JvmAttribute::Synthetic);
    }

    // ── Truncation errors ─────────────────────────────────────────────────────

    #[test]
    fn truncated_constant_value_errors() {
        let info = vec![0x00]; // only 1 byte instead of 2
        let result = JvmAttributeParser::parse_one("ConstantValue", &info, &no_cp);
        assert!(matches!(result, Err(AttrParseError::Truncated { .. })));
    }

    // ── attr.name() ───────────────────────────────────────────────────────────

    #[test]
    fn attribute_name_method() {
        assert_eq!(JvmAttribute::Deprecated.name(), "Deprecated");
        assert_eq!(JvmAttribute::Synthetic.name(), "Synthetic");
        assert_eq!(JvmAttribute::ConstantValue(0).name(), "ConstantValue");
    }

    // ── StackMapTable simple ──────────────────────────────────────────────────

    #[test]
    fn parse_stack_map_table_same_frame() {
        let mut v = Vec::new();
        v.extend_from_slice(&1u16.to_be_bytes()); // number_of_entries
        v.push(0u8); // same_frame with offset 0
        let attr = JvmAttributeParser::parse_one("StackMapTable", &v, &no_cp).unwrap();
        if let JvmAttribute::StackMapTable(frames) = attr {
            assert_eq!(frames[0].frame_type, 0);
        } else {
            panic!("wrong variant");
        }
    }

    // ── Signature ─────────────────────────────────────────────────────────────

    #[test]
    fn parse_signature_attr() {
        let mut v = Vec::new();
        v.extend_from_slice(&9u16.to_be_bytes());
        let attr = JvmAttributeParser::parse_one("Signature", &v, &no_cp).unwrap();
        assert_eq!(attr, JvmAttribute::Signature(9));
    }
}
