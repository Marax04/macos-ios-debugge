//! C type layout computation.
//!
//! Computes `sizeof` / `alignof` for every `DecompType`, inserts padding
//! fields, handles bit-field layouts (both MSVC and GCC/Clang rules), union
//! overlap, and determines whether a struct should be passed by value or by
//! reference according to the active calling convention.

use crate::{
    CallingConvention, DecompType, StructField, StructType, UnionType,
};
use rustre_decompiler_expr::IntWidth;

// ─────────────────────────────────────────────────────────────────────────────
// Layout model
// ─────────────────────────────────────────────────────────────────────────────

/// The computed layout of a type.
#[derive(Debug, Clone)]
pub struct TypeLayout {
    /// Total size in bytes (after padding).
    pub size: u64,
    /// Required alignment in bytes.
    pub alignment: u64,
    /// Byte offsets and sizes of each field, in declaration order.
    pub fields: Vec<FieldLayout>,
    /// Whether this type contains padding bytes.
    pub has_padding: bool,
}

/// Layout of a single struct/union field.
#[derive(Debug, Clone)]
pub struct FieldLayout {
    pub name: String,
    /// Byte offset from the beginning of the struct.
    pub offset: u64,
    /// Size in bytes.
    pub size: u64,
    /// Natural alignment of this field's type.
    pub alignment: u64,
    /// If this is a padding field inserted by the compiler.
    pub is_padding: bool,
    /// Bit-field width, or `None` for a regular field.
    pub bit_width: Option<u8>,
}

impl FieldLayout {
    fn padding(offset: u64, size: u64) -> Self {
        Self {
            name: format!("__pad_at_{offset:#x}"),
            offset,
            size,
            alignment: 1,
            is_padding: true,
            bit_width: None,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Compiler ABI selector
// ─────────────────────────────────────────────────────────────────────────────

/// Controls which ABI rules are used for struct layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CompilerAbi {
    /// GCC / Clang (`SystemV`) rules.
    #[default]
    GccClang,
    /// MSVC rules.
    Msvc,
}

impl CompilerAbi {
    /// Maximum alignment imposed on a field by the ABI.
    ///
    /// GCC/Clang caps at 16 bytes (for SSE types) while MSVC caps at 8 bytes
    /// for aggregates.
    #[must_use] 
    pub const fn max_alignment(self) -> u64 {
        match self {
            Self::GccClang => 16,
            Self::Msvc => 8,
        }
    }

    /// In MSVC, a bit-field of an unrelated type starts a new storage unit.
    /// In GCC, compatible bit-fields can share a storage unit across mixed
    /// types (under `-fno-ms-bit-fields`).
    #[must_use] 
    pub const fn bitfield_shares_storage_unit(self) -> bool {
        match self {
            Self::GccClang => true,
            Self::Msvc => false,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// LayoutEngine
// ─────────────────────────────────────────────────────────────────────────────

/// Computes type layouts according to a selected ABI.
#[derive(Debug, Clone)]
pub struct LayoutEngine {
    pub abi: CompilerAbi,
    /// Target pointer width in bytes (4 for 32-bit, 8 for 64-bit).
    pub pointer_size: u64,
    /// Pack alignment override (`#pragma pack`).  `None` = no packing.
    pub pack: Option<u64>,
}

impl Default for LayoutEngine {
    fn default() -> Self {
        Self {
            abi: CompilerAbi::default(),
            pointer_size: 8,
            pack: None,
        }
    }
}

impl LayoutEngine {
    /// Create a new engine for 64-bit targets with the given ABI.
    #[must_use]
    pub fn new(abi: CompilerAbi) -> Self {
        Self { abi, ..Self::default() }
    }

    /// Create a 32-bit engine.
    #[must_use]
    pub const fn x86(abi: CompilerAbi) -> Self {
        Self { abi, pointer_size: 4, pack: None }
    }

    /// Compute the natural alignment of a type.
    #[must_use]
    pub fn alignment_of(&self, ty: &DecompType) -> u64 {
        let natural = match ty {
            DecompType::Void | DecompType::Bool | DecompType::Int(IntWidth::I8 | IntWidth::U8) | DecompType::Unknown => 1,
            DecompType::Int(IntWidth::I16 | IntWidth::U16) => 2,
            DecompType::Int(IntWidth::I32 | IntWidth::U32) | DecompType::Float32 => 4,
            DecompType::Int(IntWidth::I64 | IntWidth::U64) | DecompType::Float64 => 8,
            DecompType::Ptr(_) | DecompType::FnPtr { .. } | DecompType::CStr => self.pointer_size,
            DecompType::Array(elem, _) => self.alignment_of(elem),
            DecompType::Struct(st) => self.struct_alignment(st),
            DecompType::Enum { backing, .. } => {
                self.alignment_of(&DecompType::Int(*backing))
            }
        };
        // Apply #pragma pack restriction.
        self.pack.map_or_else(|| natural.min(self.abi.max_alignment()), |pack| natural.min(pack))
    }

    /// Compute the size of a type in bytes.
    #[must_use]
    pub fn size_of(&self, ty: &DecompType) -> u64 {
        match ty {
            DecompType::Void => 0,
            DecompType::Bool | DecompType::Int(IntWidth::I8 | IntWidth::U8) => 1,
            DecompType::Int(IntWidth::I16 | IntWidth::U16) => 2,
            DecompType::Int(IntWidth::I32 | IntWidth::U32) | DecompType::Float32 => 4,
            DecompType::Int(IntWidth::I64 | IntWidth::U64) | DecompType::Float64 => 8,
            DecompType::Ptr(_) | DecompType::FnPtr { .. } | DecompType::CStr | DecompType::Unknown => self.pointer_size,
            DecompType::Array(elem, n) => self.size_of(elem).saturating_mul(*n),
            DecompType::Struct(st) => self.layout_struct(st).size,
            DecompType::Enum { backing, .. } => self.size_of(&DecompType::Int(*backing)),
        }
    }

    /// Compute the layout of a struct.
    #[must_use]
    pub fn layout_struct(&self, st: &StructType) -> TypeLayout {
        let mut fields: Vec<FieldLayout> = Vec::new();
        let mut cursor: u64 = 0;
        let mut max_align: u64 = 1;

        for field in &st.fields {
            let field_size = self.size_of(&field.ty);
            let field_align = self.alignment_of(&field.ty);
            let effective_align = self.pack.map_or(field_align, |pack| field_align.min(pack));

            max_align = max_align.max(effective_align);

            // Insert padding to reach the required alignment.
            let remainder = cursor % effective_align;
            if remainder != 0 {
                let pad = effective_align - remainder;
                fields.push(FieldLayout::padding(cursor, pad));
                cursor = cursor.saturating_add(pad);
            }

            fields.push(FieldLayout {
                name: field.name.clone(),
                offset: cursor,
                size: field_size,
                alignment: effective_align,
                is_padding: false,
                bit_width: None,
            });
            cursor = cursor.saturating_add(field_size);
        }

        // Trailing padding to round the struct size up to its alignment.
        let remainder = cursor % max_align;
        let has_trailing_pad = remainder != 0;
        if has_trailing_pad {
            let pad = max_align - remainder;
            fields.push(FieldLayout::padding(cursor, pad));
            cursor = cursor.saturating_add(pad);
        }

        let has_padding = fields.iter().any(|f| f.is_padding);

        TypeLayout {
            size: cursor,
            alignment: max_align,
            fields,
            has_padding,
        }
    }

    /// Compute the layout of a union.
    ///
    /// All members start at offset 0; the total size is the size of the
    /// largest member, rounded up to the maximum member alignment.
    #[must_use]
    pub fn layout_union(&self, u: &UnionType) -> TypeLayout {
        let mut max_size: u64 = 0;
        let mut max_align: u64 = 1;
        let mut fields: Vec<FieldLayout> = Vec::new();

        for member in &u.members {
            let member_size = self.size_of(&member.ty);
            let member_align = self.alignment_of(&member.ty);
            max_size = max_size.max(member_size);
            max_align = max_align.max(member_align);
            fields.push(FieldLayout {
                name: member.name.clone(),
                offset: 0,
                size: member_size,
                alignment: member_align,
                is_padding: false,
                bit_width: None,
            });
        }

        // Round total size up to alignment.
        let rem = max_size % max_align;
        let total_size = if rem == 0 {
            max_size
        } else {
            max_size.saturating_add(max_align - rem)
        };

        TypeLayout {
            size: total_size,
            alignment: max_align,
            fields,
            has_padding: false,
        }
    }

    /// Compute the alignment required for a struct based on its fields.
    fn struct_alignment(&self, st: &StructType) -> u64 {
        st.fields
            .iter()
            .map(|f| self.alignment_of(&f.ty))
            .max()
            .unwrap_or(1)
            .min(self.abi.max_alignment())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Bit-field layout
// ─────────────────────────────────────────────────────────────────────────────

/// A bit-field declaration within a struct.
#[derive(Debug, Clone)]
pub struct BitField {
    pub name: String,
    /// Underlying storage type.
    pub storage_type: IntWidth,
    /// Width of the bit-field in bits.
    pub width: u8,
}

/// Computed bit-field layout for a sequence of bit-fields.
#[derive(Debug, Clone)]
pub struct BitFieldLayout {
    /// Total size in bytes of all storage units consumed.
    pub total_bytes: u64,
    /// Each bit-field: (name, `byte_offset`, `bit_offset_within_byte`, `width_bits`).
    pub fields: Vec<(String, u64, u8, u8)>,
}

/// Lay out a sequence of bit-fields according to the selected ABI.
///
/// # Rules (simplified)
///
/// **MSVC:**
/// * A bit-field must fit in its underlying storage unit.
/// * Unnamed zero-width bit-fields (`int :0`) force alignment to the next
///   storage-unit boundary.
/// * Different underlying types always start a new storage unit.
///
/// **GCC/Clang:**
/// * Bit-fields are packed as tightly as possible.
/// * Different underlying types may share a storage unit.
#[must_use]
pub fn layout_bit_fields(fields: &[BitField], abi: CompilerAbi) -> BitFieldLayout {
    let mut result: Vec<(String, u64, u8, u8)> = Vec::new();
    let mut byte_offset: u64 = 0;
    let mut bit_offset: u8 = 0;
    let mut current_storage_bits: u8 = 0;
    let mut current_storage_type: Option<IntWidth> = None;

    for field in fields {
        let storage_bits = u8::try_from(field.storage_type.bits()).unwrap_or(u8::MAX);

        // Zero-width: align to next storage unit boundary.
        if field.width == 0 {
            if bit_offset > 0 {
                byte_offset += u64::from(current_storage_bits).div_ceil(8);
                bit_offset = 0;
                current_storage_bits = 0;
                current_storage_type = None;
            }
            continue;
        }

        let needs_new_unit = match abi {
            CompilerAbi::Msvc => {
                // MSVC: new type → new unit, OR bit-field doesn't fit.
                current_storage_type.is_none()
                    || current_storage_type != Some(field.storage_type)
                    || bit_offset + field.width > storage_bits
            }
            CompilerAbi::GccClang => {
                // GCC: start a new unit if the field doesn't fit in the current one.
                current_storage_type.is_none() || bit_offset + field.width > storage_bits
            }
        };

        if needs_new_unit {
            if current_storage_bits > 0 {
                byte_offset += u64::from(current_storage_bits).div_ceil(8);
            }
            bit_offset = 0;
            current_storage_bits = storage_bits;
            current_storage_type = Some(field.storage_type);
        }

        result.push((field.name.clone(), byte_offset, bit_offset, field.width));
        bit_offset += field.width;
    }

    // Final storage unit.
    if bit_offset > 0 {
        byte_offset += u64::from(current_storage_bits).div_ceil(8);
    }

    BitFieldLayout {
        total_bytes: byte_offset,
        fields: result,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Calling-convention struct-passing rules
// ─────────────────────────────────────────────────────────────────────────────

/// Determines how a struct argument should be passed to a function.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StructPassingMode {
    /// The struct fits in registers and is passed by value.
    ByValue,
    /// The struct is too large or has alignment requirements; pass a pointer.
    ByPointer,
    /// The struct is split across two 64-bit integer registers (`SysV` x64 eightbyte rules).
    SplitRegisters,
}

/// Compute how a struct should be passed according to the calling convention.
#[must_use]
pub const fn struct_passing_mode(
    layout: &TypeLayout,
    cc: CallingConvention,
) -> StructPassingMode {
    match cc {
        // SysV AMD64: structs ≤ 16 bytes with only INTEGER/SSE classes →
        //   split across two registers.
        CallingConvention::SysV64 => {
            if layout.size <= 8 {
                StructPassingMode::ByValue
            } else if layout.size <= 16 {
                StructPassingMode::SplitRegisters
            } else {
                StructPassingMode::ByPointer
            }
        }
        // MSVC x64: structs of 1/2/4/8 bytes → by value; everything else
        //   → by pointer (hidden first argument).
        CallingConvention::MsX64 => {
            if matches!(layout.size, 1 | 2 | 4 | 8) {
                StructPassingMode::ByValue
            } else {
                StructPassingMode::ByPointer
            }
        }
        // 32-bit x86: structs are almost always passed by pointer.
        CallingConvention::CDecl | CallingConvention::StdCall => {
            if layout.size <= 4 {
                StructPassingMode::ByValue
            } else {
                StructPassingMode::ByPointer
            }
        }
        // FastCall / ThisCall: similar to MSVC.
        CallingConvention::FastCall | CallingConvention::ThisCall => {
            if matches!(layout.size, 1 | 2 | 4) {
                StructPassingMode::ByValue
            } else {
                StructPassingMode::ByPointer
            }
        }
        CallingConvention::Custom => StructPassingMode::ByPointer,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Padding insertion helper
// ─────────────────────────────────────────────────────────────────────────────

/// Rebuild a `StructType` with explicit padding fields inserted.
///
/// Useful for emitting the struct declaration with explicit `uint8_t __padN[k]`
/// members so that the declared struct has the exact binary layout.
#[must_use]
pub fn insert_padding_fields(st: &StructType, engine: &LayoutEngine) -> StructType {
    let layout = engine.layout_struct(st);
    let mut new_fields: Vec<StructField> = Vec::new();

    for fl in &layout.fields {
        if fl.is_padding {
            let pad_ty = if fl.size == 1 {
                DecompType::Int(IntWidth::U8)
            } else {
                DecompType::Array(Box::new(DecompType::Int(IntWidth::U8)), fl.size)
            };
            new_fields.push(StructField {
                offset: fl.offset,
                name: fl.name.clone(),
                ty: pad_ty,
            });
        } else {
            // Find the original field from the struct.
            if let Some(orig) = st.fields.iter().find(|f| f.name == fl.name) {
                new_fields.push(orig.clone());
            }
        }
    }

    StructType {
        name: st.name.clone(),
        fields: new_fields,
        total_size: layout.size,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// C declaration emitter
// ─────────────────────────────────────────────────────────────────────────────

/// Emit a `sizeof(type)` annotation as a C comment.
#[must_use]
pub fn emit_sizeof_comment(ty: &DecompType, engine: &LayoutEngine) -> String {
    let sz = engine.size_of(ty);
    let al = engine.alignment_of(ty);
    format!("/* sizeof={sz}, alignof={al} */")
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::StructField;

    fn i8() -> DecompType { DecompType::Int(IntWidth::I8) }
    fn i16() -> DecompType { DecompType::Int(IntWidth::I16) }
    fn i32() -> DecompType { DecompType::Int(IntWidth::I32) }
    fn i64() -> DecompType { DecompType::Int(IntWidth::I64) }
    fn u8_ty() -> DecompType { DecompType::Int(IntWidth::U8) }

    fn engine() -> LayoutEngine { LayoutEngine::new(CompilerAbi::GccClang) }
    fn msvc_engine() -> LayoutEngine { LayoutEngine::new(CompilerAbi::Msvc) }

    // ── size_of ───────────────────────────────────────────────────────────────

    #[test]
    fn test_size_of_primitives() {
        let e = engine();
        assert_eq!(e.size_of(&i8()), 1);
        assert_eq!(e.size_of(&i16()), 2);
        assert_eq!(e.size_of(&i32()), 4);
        assert_eq!(e.size_of(&i64()), 8);
        assert_eq!(e.size_of(&DecompType::Float32), 4);
        assert_eq!(e.size_of(&DecompType::Float64), 8);
        assert_eq!(e.size_of(&DecompType::Bool), 1);
    }

    #[test]
    fn test_size_of_pointer() {
        assert_eq!(engine().size_of(&DecompType::Ptr(Box::new(DecompType::Void))), 8);
        assert_eq!(LayoutEngine::x86(CompilerAbi::GccClang)
            .size_of(&DecompType::Ptr(Box::new(DecompType::Void))), 4);
    }

    #[test]
    fn test_size_of_array() {
        let e = engine();
        let arr = DecompType::Array(Box::new(i32()), 10);
        assert_eq!(e.size_of(&arr), 40);
    }

    // ── alignment_of ──────────────────────────────────────────────────────────

    #[test]
    fn test_alignment_of_i32() { assert_eq!(engine().alignment_of(&i32()), 4); }
    #[test]
    fn test_alignment_of_i64() { assert_eq!(engine().alignment_of(&i64()), 8); }
    #[test]
    fn test_alignment_of_ptr_64() { assert_eq!(engine().alignment_of(&DecompType::Ptr(Box::new(DecompType::Void))), 8); }

    // ── struct layout ─────────────────────────────────────────────────────────

    #[test]
    fn test_struct_no_padding() {
        let st = StructType {
            name: "Packed".to_string(),
            fields: vec![
                StructField { offset: 0, name: "a".to_string(), ty: i32() },
                StructField { offset: 4, name: "b".to_string(), ty: i32() },
            ],
            total_size: 8,
        };
        let layout = engine().layout_struct(&st);
        assert_eq!(layout.size, 8);
        assert!(!layout.has_padding);
    }

    #[test]
    fn test_struct_with_padding() {
        // char a; int b; → 3 bytes of padding between a and b.
        let st = StructType {
            name: "WithPad".to_string(),
            fields: vec![
                StructField { offset: 0, name: "a".to_string(), ty: u8_ty() },
                StructField { offset: 1, name: "b".to_string(), ty: i32() },
            ],
            total_size: 8,
        };
        let layout = engine().layout_struct(&st);
        assert!(layout.has_padding);
        // `b` should be at offset 4 after 3 bytes of padding.
        let b_field = layout.fields.iter().find(|f| f.name == "b").unwrap();
        assert_eq!(b_field.offset, 4);
    }

    #[test]
    fn test_struct_trailing_padding() {
        // char a; int b; char c; → char c + 3 pad bytes at end.
        let st = StructType {
            name: "Trail".to_string(),
            fields: vec![
                StructField { offset: 0, name: "a".to_string(), ty: i32() },
                StructField { offset: 4, name: "b".to_string(), ty: u8_ty() },
            ],
            total_size: 8,
        };
        let layout = engine().layout_struct(&st);
        // Total size should be rounded to 4-byte alignment.
        assert_eq!(layout.size % 4, 0);
    }

    // ── union layout ──────────────────────────────────────────────────────────

    #[test]
    fn test_union_size_is_max_member() {
        let u = UnionType::new(
            "U",
            vec![
                StructField { offset: 0, name: "i".to_string(), ty: i32() },
                StructField { offset: 0, name: "ll".to_string(), ty: i64() },
                StructField { offset: 0, name: "b".to_string(), ty: u8_ty() },
            ],
        );
        let layout = engine().layout_union(&u);
        assert_eq!(layout.size, 8); // i64 dominates.
    }

    #[test]
    fn test_union_all_at_offset_zero() {
        let u = UnionType::new(
            "V",
            vec![
                StructField { offset: 0, name: "x".to_string(), ty: i32() },
                StructField { offset: 0, name: "y".to_string(), ty: i32() },
            ],
        );
        let layout = engine().layout_union(&u);
        for f in &layout.fields {
            assert_eq!(f.offset, 0);
        }
    }

    // ── bit-field layout ──────────────────────────────────────────────────────

    #[test]
    fn test_bitfield_fits_in_one_byte() {
        let fields = vec![
            BitField { name: "a".to_string(), storage_type: IntWidth::U8, width: 4 },
            BitField { name: "b".to_string(), storage_type: IntWidth::U8, width: 4 },
        ];
        let layout = layout_bit_fields(&fields, CompilerAbi::GccClang);
        assert_eq!(layout.total_bytes, 1);
    }

    #[test]
    fn test_bitfield_zero_width_aligns() {
        let fields = vec![
            BitField { name: "a".to_string(), storage_type: IntWidth::U8, width: 3 },
            BitField { name: "".to_string(), storage_type: IntWidth::U8, width: 0 },
            BitField { name: "b".to_string(), storage_type: IntWidth::U8, width: 5 },
        ];
        let layout = layout_bit_fields(&fields, CompilerAbi::GccClang);
        // After the zero-width, `b` starts in a new byte.
        let b = layout.fields.iter().find(|(n, ..)| n == "b").unwrap();
        assert_eq!(b.2, 0); // bit_offset = 0 (start of new byte).
    }

    // ── calling convention passing ────────────────────────────────────────────

    #[test]
    fn test_sysv_small_struct_by_value() {
        let layout = TypeLayout { size: 8, alignment: 8, fields: vec![], has_padding: false };
        assert_eq!(struct_passing_mode(&layout, CallingConvention::SysV64), StructPassingMode::ByValue);
    }

    #[test]
    fn test_sysv_medium_struct_split() {
        let layout = TypeLayout { size: 16, alignment: 8, fields: vec![], has_padding: false };
        assert_eq!(struct_passing_mode(&layout, CallingConvention::SysV64), StructPassingMode::SplitRegisters);
    }

    #[test]
    fn test_sysv_large_struct_by_pointer() {
        let layout = TypeLayout { size: 32, alignment: 8, fields: vec![], has_padding: false };
        assert_eq!(struct_passing_mode(&layout, CallingConvention::SysV64), StructPassingMode::ByPointer);
    }

    #[test]
    fn test_msvc_4_byte_by_value() {
        let layout = TypeLayout { size: 4, alignment: 4, fields: vec![], has_padding: false };
        assert_eq!(struct_passing_mode(&layout, CallingConvention::MsX64), StructPassingMode::ByValue);
    }

    #[test]
    fn test_msvc_3_byte_by_pointer() {
        let layout = TypeLayout { size: 3, alignment: 1, fields: vec![], has_padding: false };
        assert_eq!(struct_passing_mode(&layout, CallingConvention::MsX64), StructPassingMode::ByPointer);
    }

    // ── insert_padding_fields ─────────────────────────────────────────────────

    #[test]
    fn test_insert_padding_adds_fields() {
        let st = StructType {
            name: "P".to_string(),
            fields: vec![
                StructField { offset: 0, name: "a".to_string(), ty: u8_ty() },
                StructField { offset: 1, name: "b".to_string(), ty: i32() },
            ],
            total_size: 8,
        };
        let padded = insert_padding_fields(&st, &engine());
        assert!(padded.fields.iter().any(|f| f.name.starts_with("__pad")));
    }

    // ── sizeof comment ────────────────────────────────────────────────────────

    #[test]
    fn test_sizeof_comment_i32() {
        let s = emit_sizeof_comment(&i32(), &engine());
        assert!(s.contains("sizeof=4"));
        assert!(s.contains("alignof=4"));
    }
}
