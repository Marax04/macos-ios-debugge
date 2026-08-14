//! `struct_builder` — struct-type recovery from field-access observations.
//!
//! The `StructBuilder` records every memory access at a (base-pointer,
//! offset) pair and, when asked to `build_struct`, synthesises a `StructType`
//! with inferred field names, sizes, and padding.

use std::collections::{BTreeMap, HashMap};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::constraints::Address;

// ── FieldAccess ───────────────────────────────────────────────────────────────

/// One observed access to a struct field.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldAccess {
    /// Byte size of the access.
    pub size: u8,
    /// True if this was a read (LOAD); false if a write (STORE).
    pub is_read: bool,
    /// Number of times this exact (offset, size, direction) was observed.
    pub access_count: u32,
    /// The function address from which the access originated.
    pub from_function: Address,
}

// ── Field ─────────────────────────────────────────────────────────────────────

/// A recovered field in a struct type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Field {
    pub offset: u64,
    pub size: u8,
    pub name: String,
    /// Inferred C type name (e.g. `"uint32_t"`, `"void *"`).
    pub type_name: String,
    /// Total observed accesses (reads + writes).
    pub access_count: u32,
    /// Number of distinct functions that accessed this field.
    pub accessor_count: usize,
}

impl fmt::Display for Field {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "+{:#06x}  {}  {};   // accessed {} times",
            self.offset, self.type_name, self.name, self.access_count
        )
    }
}

// ── PaddingField ──────────────────────────────────────────────────────────────

/// A gap between two known fields (or at the start/end of the struct) that
/// is likely alignment padding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PaddingField {
    pub offset: u64,
    pub size: u64,
}

// ── StructType ────────────────────────────────────────────────────────────────

/// A recovered struct type.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StructType {
    pub name: String,
    pub fields: Vec<Field>,
    pub padding: Vec<PaddingField>,
    /// Minimum known struct size (offset of last field + its size).
    pub min_size: u64,
}

impl StructType {
    /// Render the struct as a C declaration string.
    #[must_use]
    pub fn to_c_decl(&self) -> String {
        use std::fmt::Write as _;
        let mut out = format!("typedef struct {} {{\n", self.name);
        for field in &self.fields {
            let _ = writeln!(out, "    {}  {};", field.type_name, field.name);
        }
        let _ = writeln!(out, "}} {}; // sizeof >= {}", self.name, self.min_size);
        out
    }
}

// ── StructBuilder ─────────────────────────────────────────────────────────────

/// Collects field accesses and synthesises a `StructType`.
#[derive(Debug, Clone, Default)]
pub struct StructBuilder {
    /// Maps byte offset → list of `FieldAccess` records.
    accesses: BTreeMap<u64, Vec<FieldAccess>>,
}

impl StructBuilder {
    /// Create an empty builder.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record one observed field access.
    pub fn record_access(&mut self, offset: u64, size: u8, is_read: bool, from_fn: Address) {
        let bucket = self.accesses.entry(offset).or_default();
        // If an identical (size, direction, from_fn) entry already exists, just
        // increment its counter.
        if let Some(existing) = bucket
            .iter_mut()
            .find(|a| a.size == size && a.is_read == is_read && a.from_function.0 == from_fn.0)
        {
            existing.access_count += 1;
        } else {
            bucket.push(FieldAccess {
                size,
                is_read,
                access_count: 1,
                from_function: from_fn,
            });
        }
    }

    /// Build a `StructType` from all accumulated observations.
    #[must_use]
    pub fn build_struct(&self, name: &str) -> StructType {
        let mut fields: Vec<Field> = Vec::new();

        for (&offset, access_list) in &self.accesses {
            // Determine the dominant access size: pick the mode (most frequent).
            let mut size_count: HashMap<u8, u32> = HashMap::new();
            for a in access_list {
                *size_count.entry(a.size).or_insert(0) += a.access_count;
            }
            // Tie-break deterministically: `max_by_key(count)` alone over a
            // HashMap returns a hash-iteration-order-dependent winner when
            // two sizes have equal counts. Prefer the smaller size on ties.
            let dom_size = size_count
                .iter()
                .max_by_key(|&(s, c)| (*c, std::cmp::Reverse(*s)))
                .map_or(4, |(s, _)| *s);

            let total_accesses: u32 = access_list.iter().map(|a| a.access_count).sum();
            let accessor_count = access_list
                .iter()
                .map(|a| a.from_function.0)
                .collect::<std::collections::HashSet<_>>()
                .len();

            let type_name = infer_field_type(dom_size);
            let field_name = format!("field_{offset:#x}");

            fields.push(Field {
                offset,
                size: dom_size,
                name: field_name,
                type_name,
                access_count: total_accesses,
                accessor_count,
            });
        }

        // Sort fields by offset (BTreeMap already in order, but let's be explicit).
        fields.sort_by_key(|f| f.offset);

        let min_size = fields
            .last()
            .map_or(0, |f| f.offset.saturating_add(u64::from(f.size)));

        let padding = infer_padding_gaps(&fields);

        StructType {
            name: name.to_string(),
            fields,
            padding,
            min_size,
        }
    }

    /// Merge another `StructBuilder` into this one (combining field observations).
    pub fn merge_with(&mut self, other: &Self) {
        for (&offset, access_list) in &other.accesses {
            for a in access_list {
                // Merge by directly inserting the batch rather than replaying
                // a.access_count individual calls. Replaying a.access_count
                // times would loop up to u32::MAX iterations on adversarial
                // input (DoS via unbounded loop).
                let bucket = self.accesses.entry(offset).or_default();
                if let Some(existing) = bucket
                    .iter_mut()
                    .find(|x| x.size == a.size && x.is_read == a.is_read && x.from_function.0 == a.from_function.0)
                {
                    existing.access_count = existing.access_count.saturating_add(a.access_count);
                } else {
                    bucket.push(a.clone());
                }
            }
        }
    }

    /// Total number of distinct observed offsets.
    #[must_use]
    pub fn field_count(&self) -> usize {
        self.accesses.len()
    }

    /// True when no accesses have been recorded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.accesses.is_empty()
    }

    /// Return all distinct offsets that have been accessed.
    #[must_use]
    pub fn offsets(&self) -> Vec<u64> {
        self.accesses.keys().copied().collect()
    }

    /// Return a reference to the raw accesses map.
    #[must_use]
    pub const fn raw_accesses(&self) -> &BTreeMap<u64, Vec<FieldAccess>> {
        &self.accesses
    }

    /// Compute padding fields that would appear between observed fields when
    /// the struct is laid out with natural alignment.
    #[must_use]
    pub fn infer_padding(&self) -> Vec<PaddingField> {
        let st = self.build_struct("<temp>");
        st.padding
    }
}

// ── helpers ───────────────────────────────────────────────────────────────────

/// Guess a C type name from the access size alone.
fn infer_field_type(size: u8) -> String {
    match size {
        1 => "uint8_t".into(),
        2 => "uint16_t".into(),
        4 => "uint32_t".into(),
        8 => "uint64_t".into(),
        16 => "__m128".into(),
        _ => format!("uint8_t[{size}]"),
    }
}

/// Compute gaps between consecutive fields.
fn infer_padding_gaps(fields: &[Field]) -> Vec<PaddingField> {
    let mut gaps = Vec::new();
    for window in fields.windows(2) {
        let (prev, next) = (&window[0], &window[1]);
        let prev_end = prev.offset.saturating_add(u64::from(prev.size));
        if next.offset > prev_end {
            gaps.push(PaddingField {
                offset: prev_end,
                size: next.offset - prev_end,
            });
        }
    }
    gaps
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(a: u64) -> Address {
        Address(a)
    }

    #[test]
    fn test_builder_basic_struct() {
        let mut b = StructBuilder::new();
        b.record_access(0, 4, true, addr(0x1000));
        b.record_access(4, 8, false, addr(0x1000));
        b.record_access(12, 4, true, addr(0x1000));
        let s = b.build_struct("Foo");
        assert_eq!(s.name, "Foo");
        assert_eq!(s.fields.len(), 3);
        assert_eq!(s.fields[0].offset, 0);
        assert_eq!(s.fields[1].offset, 4);
        assert_eq!(s.fields[2].offset, 12);
    }

    #[test]
    fn test_builder_min_size() {
        let mut b = StructBuilder::new();
        b.record_access(0, 4, true, addr(0));
        b.record_access(16, 8, true, addr(0));
        let s = b.build_struct("Bar");
        assert_eq!(s.min_size, 24); // 16 + 8
    }

    #[test]
    fn test_builder_padding_detected() {
        let mut b = StructBuilder::new();
        b.record_access(0, 4, true, addr(0));
        b.record_access(8, 8, true, addr(0)); // gap of 4 bytes at offset 4
        let s = b.build_struct("Gapped");
        assert_eq!(s.padding.len(), 1);
        assert_eq!(s.padding[0].offset, 4);
        assert_eq!(s.padding[0].size, 4);
    }

    #[test]
    fn test_builder_dedup_same_access() {
        let mut b = StructBuilder::new();
        b.record_access(0, 4, true, addr(0x1000));
        b.record_access(0, 4, true, addr(0x1000));
        b.record_access(0, 4, true, addr(0x1000));
        let s = b.build_struct("X");
        assert_eq!(s.fields.len(), 1);
        assert_eq!(s.fields[0].access_count, 3);
    }

    #[test]
    fn test_builder_dominant_size() {
        let mut b = StructBuilder::new();
        // Three 4-byte reads vs one 1-byte read → dominant size should be 4.
        b.record_access(0, 4, true, addr(0x100));
        b.record_access(0, 4, true, addr(0x200));
        b.record_access(0, 4, true, addr(0x300));
        b.record_access(0, 1, true, addr(0x400));
        let s = b.build_struct("D");
        assert_eq!(s.fields[0].size, 4);
    }

    #[test]
    fn test_builder_merge() {
        let mut a = StructBuilder::new();
        a.record_access(0, 4, true, addr(0));
        let mut b_b = StructBuilder::new();
        b_b.record_access(8, 8, true, addr(0));
        a.merge_with(&b_b);
        assert_eq!(a.field_count(), 2);
    }

    #[test]
    fn test_builder_c_decl() {
        let mut b = StructBuilder::new();
        b.record_access(0, 4, true, addr(0));
        let s = b.build_struct("MyStruct");
        let decl = s.to_c_decl();
        assert!(decl.contains("MyStruct"));
        assert!(decl.contains("uint32_t"));
    }

    #[test]
    fn test_builder_is_empty() {
        let b = StructBuilder::new();
        assert!(b.is_empty());
    }

    #[test]
    fn test_builder_offsets() {
        let mut b = StructBuilder::new();
        b.record_access(0, 4, true, addr(0));
        b.record_access(8, 8, true, addr(0));
        let offsets = b.offsets();
        assert_eq!(offsets, vec![0u64, 8u64]);
    }

    #[test]
    fn test_infer_padding_helper() {
        let mut b = StructBuilder::new();
        b.record_access(0, 4, true, addr(0));
        b.record_access(16, 4, true, addr(0));
        let pad = b.infer_padding();
        assert_eq!(pad.len(), 1);
        assert_eq!(pad[0].size, 12);
    }

    #[test]
    fn test_field_type_inference() {
        assert_eq!(infer_field_type(1), "uint8_t");
        assert_eq!(infer_field_type(2), "uint16_t");
        assert_eq!(infer_field_type(4), "uint32_t");
        assert_eq!(infer_field_type(8), "uint64_t");
        assert_eq!(infer_field_type(16), "__m128");
    }

    #[test]
    fn test_multiple_function_accessors() {
        let mut b = StructBuilder::new();
        b.record_access(0, 4, true, addr(0x1000));
        b.record_access(0, 4, true, addr(0x2000));
        b.record_access(0, 4, true, addr(0x3000));
        let s = b.build_struct("MultiAccess");
        assert_eq!(s.fields[0].accessor_count, 3);
    }
}
