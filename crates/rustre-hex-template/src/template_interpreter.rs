//! `template_interpreter` — Bytecode interpreter for hex templates.
//!
//! Interprets a [`crate::Template`] against a raw byte buffer, producing an
//! [`InterpretResult`] tree of [`TypedValue`] leaves.  The interpreter handles
//! struct layout, endianness, enum discrimination, bitfield extraction, and
//! forward-reference resolution for dynamic array counts.

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::template_type_system::{
    BitfieldMember, Endianness, EnumVariant, ScalarKind, StructField, TypeKind, TypeRegistry,
    TypeSize,
};

// ─────────────────────────────────────────────────────────────────────────────
// Error
// ─────────────────────────────────────────────────────────────────────────────

/// Errors produced by the template interpreter.
#[derive(Debug, Error, Clone)]
pub enum InterpretError {
    /// Attempt to read beyond the end of the buffer.
    #[error("read out of bounds at offset {offset:#x}: need {need} bytes, have {have}")]
    OutOfBounds {
        offset: usize,
        need: usize,
        have: usize,
    },
    /// A named field required by a dynamic array count was not found.
    #[error("count field '{0}' not found in context")]
    CountFieldMissing(String),
    /// A named type was referenced but not registered.
    #[error("type '{0}' not found in registry")]
    TypeNotFound(String),
    /// Recursion depth exceeded.
    #[error("recursion depth exceeded ({0})")]
    RecursionLimit(usize),
    /// A type size could not be determined statically.
    #[error("type size unknown for '{0}'")]
    SizeUnknown(String),
    /// An enum value did not match any registered variant.
    #[error("enum discriminant {0} not found in variant list")]
    UnknownVariant(u64),
    /// General interpretation error.
    #[error("interpret error: {0}")]
    General(String),
}

// ─────────────────────────────────────────────────────────────────────────────
// TypedValue
// ─────────────────────────────────────────────────────────────────────────────

/// A resolved value produced by the interpreter.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum TypedValue {
    /// Unsigned integer up to 64 bits.
    UInt(u64),
    /// Signed integer up to 64 bits.
    SInt(i64),
    /// IEEE-754 float (stored as f64 for uniformity).
    Float(f64),
    /// Raw byte slice.
    Bytes(Vec<u8>),
    /// UTF-8 string (from CStr, LenPrefix, etc.).
    Str(String),
    /// GUID displayed in `{XXXXXXXX-...}` format.
    Guid([u8; 16]),
    /// Pointer address.
    Pointer(u64),
    /// Named enum variant and its raw discriminant.
    Enum { name: String, raw: u64 },
    /// Bitfield: map of member name → extracted value.
    Bitfield(HashMap<String, u64>),
    /// Nested struct fields.
    Struct(Vec<InterpretResult>),
    /// Array of values.
    Array(Vec<TypedValue>),
    /// Padding — no data.
    Padding,
}

impl TypedValue {
    /// Try to interpret this value as a `u64` for use in conditions / counts.
    #[must_use]
    pub const fn as_u64(&self) -> Option<u64> {
        match self {
            Self::UInt(v) => Some(*v),
            Self::SInt(v) => Some(*v as u64),
            Self::Float(v) => Some(*v as u64),
            Self::Pointer(v) => Some(*v),
            Self::Enum { raw, .. } => Some(*raw),
            _ => None,
        }
    }

    /// Returns `true` if this is a scalar integer.
    #[must_use]
    pub const fn is_integer(&self) -> bool {
        matches!(self, Self::UInt(_) | Self::SInt(_))
    }
}

impl fmt::Display for TypedValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UInt(v) => write!(f, "{v:#x}"),
            Self::SInt(v) => write!(f, "{v}"),
            Self::Float(v) => write!(f, "{v}"),
            Self::Bytes(b) => write!(f, "[{} bytes]", b.len()),
            Self::Str(s) => write!(f, "\"{s}\""),
            Self::Guid(g) => {
                let d1 = u32::from_le_bytes([g[0], g[1], g[2], g[3]]);
                let d2 = u16::from_le_bytes([g[4], g[5]]);
                let d3 = u16::from_le_bytes([g[6], g[7]]);
                write!(
                    f,
                    "{{{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}}}",
                    d1, d2, d3, g[8], g[9], g[10], g[11], g[12], g[13], g[14], g[15]
                )
            }
            Self::Pointer(v) => write!(f, "ptr:{v:#x}"),
            Self::Enum { name, raw } => write!(f, "{name}({raw:#x})"),
            Self::Bitfield(m) => write!(f, "{{bitfield: {} members}}", m.len()),
            Self::Struct(fields) => write!(f, "{{struct: {} fields}}", fields.len()),
            Self::Array(v) => write!(f, "[array: {} elements]", v.len()),
            Self::Padding => write!(f, "<pad>"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// InterpretResult
// ─────────────────────────────────────────────────────────────────────────────

/// A single resolved field from running the template interpreter.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InterpretResult {
    /// Field name.
    pub name: String,
    /// Byte offset in the input buffer at which this field was read.
    pub offset: usize,
    /// Byte size consumed.
    pub size: usize,
    /// The resolved value.
    pub value: TypedValue,
}

impl InterpretResult {
    /// Convenience accessor: returns `value.as_u64()`.
    #[must_use]
    pub fn as_u64(&self) -> Option<u64> {
        self.value.as_u64()
    }
}

impl fmt::Display for InterpretResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "+{:#06x} [{:4}] {} = {}",
            self.offset, self.size, self.name, self.value
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// InterpretContext
// ─────────────────────────────────────────────────────────────────────────────

/// Evaluation context: maps field names to their resolved `u64` values.
///
/// Used to resolve dynamic array counts and expression operands.
#[derive(Debug, Default, Clone)]
pub struct InterpretContext {
    values: HashMap<String, u64>,
}

impl InterpretContext {
    /// Create an empty context.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a field value.
    pub fn set(&mut self, name: impl Into<String>, val: u64) {
        self.values.insert(name.into(), val);
    }

    /// Look up a field value by name.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<u64> {
        self.values.get(name).copied()
    }

    /// Merge another context into this one (other takes priority).
    pub fn merge(&mut self, other: &Self) {
        for (k, v) in &other.values {
            self.values.insert(k.clone(), *v);
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TemplateInterpreter
// ─────────────────────────────────────────────────────────────────────────────

const MAX_DEPTH: usize = 64;

/// The main interpreter engine.
///
/// Reads fields from a byte buffer according to [`TypeKind`] descriptors,
/// tracking the current parse cursor and building an [`InterpretResult`] tree.
pub struct TemplateInterpreter<'a> {
    buf: &'a [u8],
    registry: &'a TypeRegistry,
}

impl<'a> TemplateInterpreter<'a> {
    /// Create a new interpreter for `buf` with the given type registry.
    #[must_use]
    pub const fn new(buf: &'a [u8], registry: &'a TypeRegistry) -> Self {
        Self { buf, registry }
    }

    /// Borrow the type registry backing this interpreter. Useful when callers
    /// want to resolve a named type referenced by a template (e.g. to interpret
    /// a struct by name rather than by inline [`TypeKind`]).
    #[must_use]
    pub const fn registry(&self) -> &'a TypeRegistry {
        self.registry
    }

    /// Interpret a top-level named type from the registry at `offset`.
    ///
    /// Returns `None` if `type_name` is not registered.
    #[must_use]
    pub fn interpret_named(
        &self,
        type_name: &str,
        offset: usize,
        ctx: &InterpretContext,
    ) -> Option<Result<(InterpretResult, usize), InterpretError>> {
        let ty = self.registry.get(type_name)?;
        Some(self.interpret_one(type_name, &ty.kind, offset, ctx, 0))
    }

    /// Interpret a list of named struct fields starting at `base_offset`.
    ///
    /// Returns a list of [`InterpretResult`]s and the byte offset just past the
    /// last consumed byte.
    ///
    /// # Errors
    ///
    /// Returns [`InterpretError`] on buffer overrun, missing count fields, or
    /// unknown types.
    pub fn interpret_fields(
        &self,
        fields: &[StructField],
        base_offset: usize,
        ctx: &InterpretContext,
    ) -> Result<(Vec<InterpretResult>, usize), InterpretError> {
        self.interpret_fields_depth(fields, base_offset, ctx, 0)
    }

    fn interpret_fields_depth(
        &self,
        fields: &[StructField],
        base_offset: usize,
        ctx: &InterpretContext,
        depth: usize,
    ) -> Result<(Vec<InterpretResult>, usize), InterpretError> {
        if depth > MAX_DEPTH {
            return Err(InterpretError::RecursionLimit(depth));
        }
        let mut results = Vec::with_capacity(fields.len());
        let mut cursor = base_offset;
        let mut local_ctx = ctx.clone();

        for field in fields {
            let field_off = field.offset.unwrap_or(cursor);
            let (result, end) =
                self.interpret_one(&field.name, &field.ty, field_off, &local_ctx, depth)?;
            if let Some(v) = result.value.as_u64() {
                local_ctx.set(field.name.clone(), v);
            }
            cursor = end;
            results.push(result);
        }
        Ok((results, cursor))
    }

    /// Interpret a single field of `ty` at `offset`.
    pub fn interpret_one(
        &self,
        name: &str,
        ty: &TypeKind,
        offset: usize,
        ctx: &InterpretContext,
        depth: usize,
    ) -> Result<(InterpretResult, usize), InterpretError> {
        match ty {
            TypeKind::Scalar { kind, byte_width, endianness } => {
                self.interpret_scalar(name, kind, byte_width, *endianness, offset)
            }
            TypeKind::Pointer { pointer_size, endianness, .. } => {
                self.interpret_pointer(name, *pointer_size as usize, *endianness, offset)
            }
            TypeKind::Enum { underlying, variants } => {
                self.interpret_enum(name, underlying, variants, offset, ctx, depth)
            }
            TypeKind::Bitfield { parent, fields } => {
                self.interpret_bitfield(name, parent, fields, offset, ctx, depth)
            }
            TypeKind::Array { element, count } => {
                self.interpret_array(name, element, *count, offset, ctx, depth)
            }
            TypeKind::DynArray { element, count_field } => {
                const MAX_DYN_COUNT: u64 = 1_048_576; // 1 M elements
                let raw_count = ctx
                    .get(count_field)
                    .ok_or_else(|| InterpretError::CountFieldMissing(count_field.clone()))?;
                if raw_count > MAX_DYN_COUNT {
                    return Err(InterpretError::General(format!(
                        "DynArray count {raw_count} exceeds safety limit {MAX_DYN_COUNT}"
                    )));
                }
                let count = raw_count as usize;
                self.interpret_array(name, element, count, offset, ctx, depth)
            }
            TypeKind::Struct { name: sname, fields } => {
                if depth > MAX_DEPTH {
                    return Err(InterpretError::RecursionLimit(depth));
                }
                let (sub_results, end) =
                    self.interpret_fields_depth(fields, offset, ctx, depth + 1)?;
                let size = end - offset;
                // If the field has no explicit name, fall back to the struct
                // type name so the rendered tree still carries useful labels.
                let resolved = if name.is_empty() { sname.as_str() } else { name };
                Ok((
                    InterpretResult {
                        name: resolved.to_string(),
                        offset,
                        size,
                        value: TypedValue::Struct(sub_results),
                    },
                    end,
                ))
            }
            TypeKind::Union { name: _uname, members } => {
                // For a union, interpret all members from the same offset
                // and take the maximum end position.
                let mut sub_results = Vec::new();
                let mut max_end = offset;
                for m in members {
                    let (r, end) =
                        self.interpret_one(&m.name, &m.ty, offset, ctx, depth + 1)?;
                    if end > max_end {
                        max_end = end;
                    }
                    sub_results.push(r);
                }
                let size = max_end - offset;
                Ok((
                    InterpretResult {
                        name: name.to_string(),
                        offset,
                        size,
                        value: TypedValue::Struct(sub_results),
                    },
                    max_end,
                ))
            }
            TypeKind::OpaqueBytes(n) => {
                self.check_bounds(offset, *n)?;
                let bytes = self.buf[offset..offset + n].to_vec();
                Ok((
                    InterpretResult {
                        name: name.to_string(),
                        offset,
                        size: *n,
                        value: TypedValue::Bytes(bytes),
                    },
                    offset + n,
                ))
            }
            TypeKind::Padding(n) => {
                self.check_bounds(offset, *n)?;
                Ok((
                    InterpretResult {
                        name: name.to_string(),
                        offset,
                        size: *n,
                        value: TypedValue::Padding,
                    },
                    offset + n,
                ))
            }
        }
    }

    // ── Scalar ────────────────────────────────────────────────────────────────

    fn interpret_scalar(
        &self,
        name: &str,
        kind: &ScalarKind,
        byte_width: &TypeSize,
        endianness: Endianness,
        offset: usize,
    ) -> Result<(InterpretResult, usize), InterpretError> {
        match kind {
            ScalarKind::CStr => {
                if offset > self.buf.len() {
                    return Err(InterpretError::OutOfBounds {
                        offset,
                        need: 1,
                        have: self.buf.len(),
                    });
                }
                let end = self.buf[offset..]
                    .iter()
                    .position(|&b| b == 0)
                    .unwrap_or(self.buf.len() - offset);
                self.check_bounds(offset, end + 1)?;
                let s = String::from_utf8_lossy(&self.buf[offset..offset + end]).into_owned();
                let size = end + 1;
                return Ok((
                    InterpretResult {
                        name: name.to_string(),
                        offset,
                        size,
                        value: TypedValue::Str(s),
                    },
                    offset + size,
                ));
            }
            ScalarKind::WStr => {
                let mut end = offset;
                while end + 1 < self.buf.len() {
                    if self.buf[end] == 0 && self.buf[end + 1] == 0 {
                        break;
                    }
                    end += 2;
                }
                let len = end - offset;
                self.check_bounds(offset, len + 2)?;
                let u16s: Vec<u16> = self.buf[offset..offset + len]
                    .chunks_exact(2)
                    .map(|c| u16::from_le_bytes([c[0], c[1]]))
                    .collect();
                let s = String::from_utf16_lossy(&u16s);
                let size = len + 2;
                return Ok((
                    InterpretResult {
                        name: name.to_string(),
                        offset,
                        size,
                        value: TypedValue::Str(s),
                    },
                    offset + size,
                ));
            }
            ScalarKind::Guid => {
                self.check_bounds(offset, 16)?;
                let mut g = [0u8; 16];
                g.copy_from_slice(&self.buf[offset..offset + 16]);
                return Ok((
                    InterpretResult {
                        name: name.to_string(),
                        offset,
                        size: 16,
                        value: TypedValue::Guid(g),
                    },
                    offset + 16,
                ));
            }
            ScalarKind::Bytes => {
                let n = byte_width
                    .fixed()
                    .ok_or_else(|| InterpretError::SizeUnknown(name.to_string()))?;
                self.check_bounds(offset, n)?;
                let bytes = self.buf[offset..offset + n].to_vec();
                return Ok((
                    InterpretResult {
                        name: name.to_string(),
                        offset,
                        size: n,
                        value: TypedValue::Bytes(bytes),
                    },
                    offset + n,
                ));
            }
            ScalarKind::LenPrefixStr { prefix_bytes } => {
                let pfx = *prefix_bytes as usize;
                self.check_bounds(offset, pfx)?;
                let raw_len = read_uint(&self.buf[offset..offset + pfx], endianness);
                // Guard against attacker-controlled lengths exceeding buffer or usize range.
                if raw_len > self.buf.len() as u64 {
                    return Err(InterpretError::OutOfBounds {
                        offset: offset + pfx,
                        need: raw_len as usize,
                        have: self.buf.len(),
                    });
                }
                let len = raw_len as usize;
                let str_offset = offset.checked_add(pfx).ok_or(InterpretError::OutOfBounds {
                    offset,
                    need: pfx,
                    have: self.buf.len(),
                })?;
                self.check_bounds(str_offset, len)?;
                let s = String::from_utf8_lossy(&self.buf[str_offset..str_offset + len])
                    .into_owned();
                let size = pfx + len;
                return Ok((
                    InterpretResult {
                        name: name.to_string(),
                        offset,
                        size,
                        value: TypedValue::Str(s),
                    },
                    offset + size,
                ));
            }
            ScalarKind::UInt => {
                let n = byte_width
                    .fixed()
                    .ok_or_else(|| InterpretError::SizeUnknown(name.to_string()))?;
                self.check_bounds(offset, n)?;
                let val = read_uint(&self.buf[offset..offset + n], endianness);
                return Ok((
                    InterpretResult {
                        name: name.to_string(),
                        offset,
                        size: n,
                        value: TypedValue::UInt(val),
                    },
                    offset + n,
                ));
            }
            ScalarKind::SInt => {
                let n = byte_width
                    .fixed()
                    .ok_or_else(|| InterpretError::SizeUnknown(name.to_string()))?;
                self.check_bounds(offset, n)?;
                let val = read_sint(&self.buf[offset..offset + n], endianness);
                return Ok((
                    InterpretResult {
                        name: name.to_string(),
                        offset,
                        size: n,
                        value: TypedValue::SInt(val),
                    },
                    offset + n,
                ));
            }
            ScalarKind::Float => {
                let n = byte_width
                    .fixed()
                    .ok_or_else(|| InterpretError::SizeUnknown(name.to_string()))?;
                self.check_bounds(offset, n)?;
                let val = read_float(&self.buf[offset..offset + n], endianness);
                return Ok((
                    InterpretResult {
                        name: name.to_string(),
                        offset,
                        size: n,
                        value: TypedValue::Float(val),
                    },
                    offset + n,
                ));
            }
        }
    }

    // ── Pointer ───────────────────────────────────────────────────────────────

    fn interpret_pointer(
        &self,
        name: &str,
        size: usize,
        endianness: Endianness,
        offset: usize,
    ) -> Result<(InterpretResult, usize), InterpretError> {
        self.check_bounds(offset, size)?;
        let addr = read_uint(&self.buf[offset..offset + size], endianness);
        Ok((
            InterpretResult {
                name: name.to_string(),
                offset,
                size,
                value: TypedValue::Pointer(addr),
            },
            offset + size,
        ))
    }

    // ── Enum ─────────────────────────────────────────────────────────────────

    fn interpret_enum(
        &self,
        name: &str,
        underlying: &TypeKind,
        variants: &[EnumVariant],
        offset: usize,
        ctx: &InterpretContext,
        depth: usize,
    ) -> Result<(InterpretResult, usize), InterpretError> {
        let (raw_result, end) = self.interpret_one(name, underlying, offset, ctx, depth)?;
        let raw = raw_result.value.as_u64().unwrap_or(0);
        let variant_name = variants
            .iter()
            .find(|v| v.value == raw)
            .map(|v| v.name.clone())
            .unwrap_or_else(|| format!("unknown({raw:#x})"));
        let size = end - offset;
        Ok((
            InterpretResult {
                name: name.to_string(),
                offset,
                size,
                value: TypedValue::Enum {
                    name: variant_name,
                    raw,
                },
            },
            end,
        ))
    }

    // ── Bitfield ──────────────────────────────────────────────────────────────

    fn interpret_bitfield(
        &self,
        name: &str,
        parent: &TypeKind,
        fields: &[BitfieldMember],
        offset: usize,
        ctx: &InterpretContext,
        depth: usize,
    ) -> Result<(InterpretResult, usize), InterpretError> {
        let (raw_result, end) = self.interpret_one(name, parent, offset, ctx, depth)?;
        let raw = raw_result.value.as_u64().unwrap_or(0);
        let mut map = HashMap::new();
        for f in fields {
            map.insert(f.name.clone(), f.extract(raw));
        }
        let size = end - offset;
        Ok((
            InterpretResult {
                name: name.to_string(),
                offset,
                size,
                value: TypedValue::Bitfield(map),
            },
            end,
        ))
    }

    // ── Array ─────────────────────────────────────────────────────────────────

    fn interpret_array(
        &self,
        name: &str,
        element: &TypeKind,
        count: usize,
        offset: usize,
        ctx: &InterpretContext,
        depth: usize,
    ) -> Result<(InterpretResult, usize), InterpretError> {
        // Guard against huge static-array counts coming from deserialized
        // (untrusted) templates.  The same 1 M limit that DynArray enforces.
        const MAX_STATIC_COUNT: usize = 1_048_576;
        if count > MAX_STATIC_COUNT {
            return Err(InterpretError::General(format!(
                "Array count {count} exceeds safety limit {MAX_STATIC_COUNT}"
            )));
        }
        // Allocate conservatively: cap the initial reservation so a large count
        // field that turns out to be bogus does not exhaust memory before the
        // first element read fails with OutOfBounds.
        let initial_cap = count.min(4096);
        let mut values = Vec::with_capacity(initial_cap);
        let mut cursor = offset;
        for i in 0..count {
            let elem_name = format!("{name}[{i}]");
            let (r, end) = self.interpret_one(&elem_name, element, cursor, ctx, depth + 1)?;
            cursor = end;
            values.push(r.value);
        }
        let size = cursor - offset;
        Ok((
            InterpretResult {
                name: name.to_string(),
                offset,
                size,
                value: TypedValue::Array(values),
            },
            cursor,
        ))
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    const fn check_bounds(&self, offset: usize, need: usize) -> Result<(), InterpretError> {
        if offset + need > self.buf.len() {
            Err(InterpretError::OutOfBounds {
                offset,
                need,
                have: self.buf.len(),
            })
        } else {
            Ok(())
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Primitive readers
// ─────────────────────────────────────────────────────────────────────────────

fn read_uint(bytes: &[u8], endianness: Endianness) -> u64 {
    let n = bytes.len().min(8);
    let mut buf = [0u8; 8];
    match endianness {
        Endianness::Little => buf[..n].copy_from_slice(&bytes[..n]),
        Endianness::Big => buf[8 - n..].copy_from_slice(&bytes[..n]),
    }
    match endianness {
        Endianness::Little => u64::from_le_bytes(buf),
        Endianness::Big => u64::from_be_bytes(buf),
    }
}

fn read_sint(bytes: &[u8], endianness: Endianness) -> i64 {
    let raw = read_uint(bytes, endianness);
    let n = bytes.len();
    if n >= 8 {
        return raw as i64;
    }
    let sign_bit = 1u64 << (n * 8 - 1);
    if raw & sign_bit != 0 {
        let extension = !((1u64 << (n * 8)) - 1);
        (raw | extension) as i64
    } else {
        raw as i64
    }
}

fn read_float(bytes: &[u8], endianness: Endianness) -> f64 {
    match bytes.len() {
        4 => {
            let mut buf = [0u8; 4];
            buf.copy_from_slice(&bytes[..4]);
            let bits = match endianness {
                Endianness::Little => u32::from_le_bytes(buf),
                Endianness::Big => u32::from_be_bytes(buf),
            };
            f32::from_bits(bits) as f64
        }
        8 => {
            let mut buf = [0u8; 8];
            buf.copy_from_slice(&bytes[..8]);
            let bits = match endianness {
                Endianness::Little => u64::from_le_bytes(buf),
                Endianness::Big => u64::from_be_bytes(buf),
            };
            f64::from_bits(bits)
        }
        _ => 0.0,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::template_type_system::{uint_le, uint_be, sint_le, StructField, TypeRegistry};

    fn reg() -> TypeRegistry {
        TypeRegistry::with_primitives()
    }

    #[test]
    fn test_interpret_uint_le() {
        let buf = [0x34u8, 0x12, 0x00, 0x00];
        let r = TypeRegistry::with_primitives();
        let interp = TemplateInterpreter::new(&buf, &r);
        let ty = uint_le(4);
        let sf = StructField::new("val", ty);
        let (results, end) = interp
            .interpret_fields(&[sf], 0, &InterpretContext::new())
            .unwrap();
        assert_eq!(end, 4);
        assert_eq!(results[0].value, TypedValue::UInt(0x1234));
    }

    #[test]
    fn test_interpret_uint_be() {
        let buf = [0x12u8, 0x34, 0x00, 0x00];
        let r = reg();
        let interp = TemplateInterpreter::new(&buf, &r);
        let ty = uint_be(2);
        let sf = StructField::new("val", ty);
        let (results, _) = interp
            .interpret_fields(&[sf], 0, &InterpretContext::new())
            .unwrap();
        assert_eq!(results[0].value, TypedValue::UInt(0x1234));
    }

    #[test]
    fn test_interpret_sint_negative() {
        let buf = [0xFFu8, 0xFF]; // -1 as i16
        let r = reg();
        let interp = TemplateInterpreter::new(&buf, &r);
        let ty = sint_le(2);
        let sf = StructField::new("val", ty);
        let (results, _) = interp
            .interpret_fields(&[sf], 0, &InterpretContext::new())
            .unwrap();
        assert_eq!(results[0].value, TypedValue::SInt(-1));
    }

    #[test]
    fn test_interpret_cstr() {
        let buf = b"hello\0world\0";
        let r = reg();
        let interp = TemplateInterpreter::new(buf, &r);
        let ty = TypeKind::Scalar {
            kind: ScalarKind::CStr,
            byte_width: TypeSize::Unknown,
            endianness: Endianness::Little,
        };
        let sf = StructField::new("s", ty);
        let (results, end) = interp
            .interpret_fields(&[sf], 0, &InterpretContext::new())
            .unwrap();
        assert_eq!(end, 6); // "hello" + NUL
        assert_eq!(results[0].value, TypedValue::Str("hello".to_string()));
    }

    #[test]
    fn test_interpret_opaque_bytes() {
        let buf = [0xAAu8, 0xBB, 0xCC, 0xDD];
        let r = reg();
        let interp = TemplateInterpreter::new(&buf, &r);
        let ty = TypeKind::OpaqueBytes(4);
        let sf = StructField::new("raw", ty);
        let (results, _) = interp
            .interpret_fields(&[sf], 0, &InterpretContext::new())
            .unwrap();
        assert_eq!(
            results[0].value,
            TypedValue::Bytes(vec![0xAA, 0xBB, 0xCC, 0xDD])
        );
    }

    #[test]
    fn test_interpret_array() {
        let buf = [0x01u8, 0x02, 0x03];
        let r = reg();
        let interp = TemplateInterpreter::new(&buf, &r);
        let ty = TypeKind::Array {
            element: Box::new(uint_le(1)),
            count: 3,
        };
        let sf = StructField::new("arr", ty);
        let (results, _) = interp
            .interpret_fields(&[sf], 0, &InterpretContext::new())
            .unwrap();
        if let TypedValue::Array(v) = &results[0].value {
            assert_eq!(v.len(), 3);
            assert_eq!(v[0], TypedValue::UInt(1));
            assert_eq!(v[2], TypedValue::UInt(3));
        } else {
            panic!("expected array");
        }
    }

    #[test]
    fn test_interpret_dyn_array() {
        let buf = [0x03u8, 0x0A, 0x0B, 0x0C];
        let r = reg();
        let interp = TemplateInterpreter::new(&buf, &r);
        let fields = vec![
            StructField::new("count", uint_le(1)),
            StructField::new(
                "items",
                TypeKind::DynArray {
                    element: Box::new(uint_le(1)),
                    count_field: "count".to_string(),
                },
            ),
        ];
        let (results, end) = interp
            .interpret_fields(&fields, 0, &InterpretContext::new())
            .unwrap();
        assert_eq!(end, 4);
        if let TypedValue::Array(v) = &results[1].value {
            assert_eq!(v.len(), 3);
        } else {
            panic!("expected array");
        }
    }

    #[test]
    fn test_interpret_enum() {
        let buf = [0x02u8];
        let r = reg();
        let interp = TemplateInterpreter::new(&buf, &r);
        let ty = TypeKind::Enum {
            underlying: Box::new(uint_le(1)),
            variants: vec![
                crate::template_type_system::EnumVariant::new("NONE", 0),
                crate::template_type_system::EnumVariant::new("READ", 1),
                crate::template_type_system::EnumVariant::new("WRITE", 2),
            ],
        };
        let sf = StructField::new("perm", ty);
        let (results, _) = interp
            .interpret_fields(&[sf], 0, &InterpretContext::new())
            .unwrap();
        assert_eq!(
            results[0].value,
            TypedValue::Enum {
                name: "WRITE".to_string(),
                raw: 2
            }
        );
    }

    #[test]
    fn test_interpret_out_of_bounds() {
        let buf = [0x01u8, 0x02];
        let r = reg();
        let interp = TemplateInterpreter::new(&buf, &r);
        let ty = uint_le(4);
        let sf = StructField::new("val", ty);
        assert!(matches!(
            interp.interpret_fields(&[sf], 0, &InterpretContext::new()),
            Err(InterpretError::OutOfBounds { .. })
        ));
    }

    #[test]
    fn test_interpret_padding() {
        let buf = [0x00u8; 16];
        let r = reg();
        let interp = TemplateInterpreter::new(&buf, &r);
        let ty = TypeKind::Padding(8);
        let sf = StructField::new("_pad", ty);
        let (results, end) = interp
            .interpret_fields(&[sf], 0, &InterpretContext::new())
            .unwrap();
        assert_eq!(end, 8);
        assert_eq!(results[0].value, TypedValue::Padding);
    }

    #[test]
    fn test_typed_value_as_u64() {
        assert_eq!(TypedValue::UInt(42).as_u64(), Some(42));
        assert_eq!(TypedValue::SInt(-1).as_u64(), Some(u64::MAX));
        assert_eq!(TypedValue::Str("x".to_string()).as_u64(), None);
    }

    #[test]
    fn test_context_set_get() {
        let mut ctx = InterpretContext::new();
        ctx.set("foo", 99);
        assert_eq!(ctx.get("foo"), Some(99));
        assert_eq!(ctx.get("bar"), None);
    }
}
