//! Structure recovery: detect and merge struct field accesses from IL.
//!
//! Provides [`StructRecovery`], [`AccessPattern`], [`FieldCandidate`],
//! [`RecoveredStruct`], and [`StructMerger`].

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::fmt::Write as _;

use crate::type_reconstruction::ReconstructedType;

// ─── AccessOp ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AccessOp {
    Read,
    Write,
    ReadWrite,
}

impl std::fmt::Display for AccessOp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Read => write!(f, "r"),
            Self::Write => write!(f, "w"),
            Self::ReadWrite => write!(f, "rw"),
        }
    }
}

// ─── AccessPattern ────────────────────────────────────────────────────────────

/// A single observed field access on a base register/variable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessPattern {
    /// The base variable or register (e.g. "rdi", "`var_10`").
    pub base: String,
    /// The constant byte offset from the base.
    pub offset: i64,
    /// Access size in bytes (1, 2, 4, 8, …).
    pub size: u8,
    /// Read or write.
    pub op: AccessOp,
    /// Program counter / instruction address where this access occurred.
    pub address: u64,
}

impl AccessPattern {
    #[must_use] 
    pub fn new(base: &str, offset: i64, size: u8, op: AccessOp, address: u64) -> Self {
        Self {
            base: base.to_string(),
            offset,
            size,
            op,
            address,
        }
    }
}

impl std::fmt::Display for AccessPattern {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "[{}+0x{:x}]@{} ({}B {}) @ 0x{:x}",
            self.base, self.offset, self.offset, self.size, self.op, self.address
        )
    }
}

// ─── FieldCandidate ───────────────────────────────────────────────────────────

/// A candidate struct field derived from access patterns.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldCandidate {
    /// Byte offset in the struct.
    pub offset: i64,
    /// Inferred field size.
    pub size: u8,
    /// Inferred type.
    pub ty: ReconstructedType,
    /// Candidate name (auto-generated from offset).
    pub name: String,
    /// Number of times this field was accessed.
    pub access_count: u32,
    /// True if this field was written (not just read).
    pub was_written: bool,
}

impl FieldCandidate {
    fn new(offset: i64, size: u8) -> Self {
        Self {
            offset,
            size,
            ty: ReconstructedType::Unknown,
            name: format!("field_{offset:x}"),
            access_count: 1,
            was_written: false,
        }
    }

    fn merge_access(&mut self, ap: &AccessPattern) {
        self.access_count += 1;
        if ap.op == AccessOp::Write || ap.op == AccessOp::ReadWrite {
            self.was_written = true;
        }
        // Take the max observed size
        if ap.size > self.size {
            self.size = ap.size;
        }
    }

    pub fn infer_type(&mut self) {
        self.ty = match self.size {
            1 => ReconstructedType::Int(8),
            2 => ReconstructedType::Int(16),
            4 => ReconstructedType::Int(32),
            8 => ReconstructedType::Int(64),
            _ => ReconstructedType::Array(
                Box::new(ReconstructedType::Int(8)),
                Some(self.size as usize),
            ),
        };
    }
}

// ─── RecoveredStruct ──────────────────────────────────────────────────────────

/// A recovered struct: ordered list of fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveredStruct {
    /// Auto-generated or user-assigned name.
    pub name: String,
    /// Fields sorted by offset.
    pub fields: Vec<FieldCandidate>,
    /// The base variable(s) that implied this struct.
    pub bases: Vec<String>,
    /// Total inferred size (max offset + last field size).
    pub total_size: usize,
}

impl RecoveredStruct {
    #[must_use] 
    pub const fn new(name: String, bases: Vec<String>) -> Self {
        Self {
            name,
            fields: Vec::new(),
            bases,
            total_size: 0,
        }
    }

    pub fn add_field(&mut self, field: FieldCandidate) {
        let offset = field.offset;
        let size = field.size as usize;
        // Track high-water mark eagerly so total_size stays monotonic even if
        // recompute_size sees a stale snapshot during intermediate insertion.
        // Guard against negative offsets (adversarial input): skip size update if offset < 0.
        let end = usize::try_from(offset).ok().and_then(|o| o.checked_add(size)).unwrap_or(self.total_size);
        if end > self.total_size {
            self.total_size = end;
        }
        match self.fields.binary_search_by_key(&offset, |f| f.offset) {
            Ok(i) => self.fields[i].merge_access(&AccessPattern {
                base: String::new(),
                offset,
                size: field.size,
                op: AccessOp::Read,
                address: 0,
            }),
            Err(i) => self.fields.insert(i, field),
        }
        self.recompute_size();
    }

    fn recompute_size(&mut self) {
        self.total_size = self
            .fields
            .iter()
            .filter_map(|f| {
                let off = usize::try_from(f.offset).ok()?;
                off.checked_add(f.size as usize)
            })
            .max()
            .unwrap_or(0);
    }

    /// Find a field at a given offset.
    #[must_use] 
    pub fn field_at(&self, offset: i64) -> Option<&FieldCandidate> {
        self.fields.iter().find(|f| f.offset == offset)
    }

    /// True if there are gaps in the field layout.
    #[must_use] 
    pub fn has_gaps(&self) -> bool {
        let mut expected = 0i64;
        for f in &self.fields {
            if f.offset > expected {
                return true;
            }
            expected = f.offset + i64::from(f.size);
        }
        false
    }

    /// Fill gaps with unnamed padding fields.
    pub fn fill_padding(&mut self) {
        let mut filled = Vec::new();
        let mut expected = 0i64;
        for f in &self.fields {
            if f.offset > expected {
                let mut remaining = u64::try_from(f.offset - expected).unwrap_or(0);
                let mut pad_off = expected;
                while remaining > 0 {
                    let chunk = u8::try_from(remaining.min(u64::from(u8::MAX))).unwrap_or(u8::MAX);
                    let mut pad = FieldCandidate::new(pad_off, chunk);
                    pad.name = format!("_pad_{pad_off:x}");
                    pad.ty = ReconstructedType::Array(
                        Box::new(ReconstructedType::Int(8)),
                        Some(chunk as usize),
                    );
                    filled.push(pad);
                    pad_off += i64::from(chunk);
                    remaining -= u64::from(chunk);
                }
            }
            filled.push(f.clone());
            expected = f.offset + i64::from(f.size);
        }
        self.fields = filled;
    }

    #[must_use] 
    pub const fn field_count(&self) -> usize {
        self.fields.len()
    }

    /// Generate a C-like struct definition string.
    #[must_use] 
    pub fn to_c_str(&self) -> String {
        let mut s = format!("struct {} {{\n", self.name);
        for f in &self.fields {
            writeln!(s, "    {} {}; // offset=0x{:x}", f.ty.display_name(), f.name, f.offset).unwrap();
        }
        writeln!(s, "}}; // size=0x{:x}", self.total_size).unwrap();
        s
    }
}

// ─── StructRecovery ───────────────────────────────────────────────────────────

/// Main struct recovery engine: collects access patterns and produces [`RecoveredStruct`]s.
#[derive(Debug, Default)]
pub struct StructRecovery {
    /// Access patterns grouped by base variable.
    accesses: HashMap<String, Vec<AccessPattern>>,
    /// Minimum accesses required before recognizing a struct.
    min_accesses: usize,
    /// Counter for auto-naming structs.
    struct_counter: usize,
}

impl StructRecovery {
    #[must_use] 
    pub fn new() -> Self {
        Self {
            accesses: HashMap::new(),
            min_accesses: 2,
            struct_counter: 0,
        }
    }

    #[must_use] 
    pub const fn with_min_accesses(mut self, n: usize) -> Self {
        self.min_accesses = n;
        self
    }

    /// Record a single memory access pattern.
    pub fn record(&mut self, ap: AccessPattern) {
        self.accesses.entry(ap.base.clone()).or_default().push(ap);
    }

    /// Record multiple accesses.
    pub fn record_many(&mut self, patterns: impl IntoIterator<Item = AccessPattern>) {
        for ap in patterns {
            self.record(ap);
        }
    }

    /// Run structure recovery on all collected accesses.
    pub fn recover(&mut self) -> Vec<RecoveredStruct> {
        let mut structs = Vec::new();

        for (base, patterns) in &self.accesses {
            // Skip bases with only one unique offset (probably not a struct)
            let unique_offsets: std::collections::HashSet<i64> =
                patterns.iter().map(|p| p.offset).collect();
            if unique_offsets.len() < self.min_accesses {
                continue;
            }

            let name = format!("Struct_{}", self.struct_counter);
            self.struct_counter += 1;

            let mut s = RecoveredStruct::new(name, vec![base.clone()]);

            // Group accesses by offset
            let mut by_offset: BTreeMap<i64, Vec<&AccessPattern>> = BTreeMap::new();
            for ap in patterns {
                by_offset.entry(ap.offset).or_default().push(ap);
            }

            for (offset, aps) in by_offset {
                let max_size = aps.iter().map(|a| a.size).max().unwrap_or(4);
                let mut field = FieldCandidate::new(offset, max_size);
                field.access_count = u32::try_from(aps.len()).unwrap_or(u32::MAX);
                field.was_written = aps
                    .iter()
                    .any(|a| a.op == AccessOp::Write || a.op == AccessOp::ReadWrite);
                field.infer_type();
                s.add_field(field);
            }

            structs.push(s);
        }

        structs
    }

    /// All bases that have been observed.
    #[must_use] 
    pub fn known_bases(&self) -> Vec<&String> {
        self.accesses.keys().collect()
    }

    /// Access count for a given base.
    #[must_use] 
    pub fn access_count_for(&self, base: &str) -> usize {
        self.accesses.get(base).map_or(0, std::vec::Vec::len)
    }
}

// ─── StructMerger ─────────────────────────────────────────────────────────────

/// Merges two [`RecoveredStruct`]s that may represent the same underlying type.
pub struct StructMerger;

impl StructMerger {
    #[must_use] 
    pub const fn new() -> Self {
        Self
    }

    /// Attempt to merge `a` and `b` if they have overlapping fields.
    /// Returns Some(merged) if compatible, None if incompatible.
    #[must_use] 
    pub fn merge(&self, a: &RecoveredStruct, b: &RecoveredStruct) -> Option<RecoveredStruct> {
        let compat = self.compatibility_score(a, b);
        if compat < 0.5 {
            return None;
        }

        let mut combined = RecoveredStruct::new(
            format!("{}_{}", a.name, b.name),
            a.bases.iter().chain(b.bases.iter()).cloned().collect(),
        );

        // Merge all fields from both structs
        for f in &a.fields {
            combined.add_field(f.clone());
        }
        for f in &b.fields {
            if combined.field_at(f.offset).is_none() {
                combined.add_field(f.clone());
            }
        }

        Some(combined)
    }

    /// Compatibility score 0.0 (incompatible) .. 1.0 (identical).
    #[must_use] 
    pub fn compatibility_score(&self, a: &RecoveredStruct, b: &RecoveredStruct) -> f64 {
        if a.fields.is_empty() || b.fields.is_empty() {
            return 0.0;
        }

        let a_offsets: std::collections::HashSet<i64> = a.fields.iter().map(|f| f.offset).collect();
        let b_offsets: std::collections::HashSet<i64> = b.fields.iter().map(|f| f.offset).collect();
        let intersection = a_offsets.intersection(&b_offsets).count();
        let union = a_offsets.union(&b_offsets).count();

        if union == 0 {
            0.0
        } else {
            f64::from(u32::try_from(intersection.min(u32::MAX as usize)).unwrap_or(u32::MAX))
                / f64::from(u32::try_from(union.min(u32::MAX as usize)).unwrap_or(u32::MAX))
        }
    }

    /// Merge a list of structs greedily by highest compatibility.
    #[must_use] 
    pub fn merge_all(&self, structs: Vec<RecoveredStruct>) -> Vec<RecoveredStruct> {
        let mut result: Vec<RecoveredStruct> = Vec::new();
        for s in structs {
            let mut merged = false;
            for existing in &mut result {
                if self.compatibility_score(existing, &s) >= 0.6
                    && let Some(m) = self.merge(existing, &s) {
                        *existing = m;
                        merged = true;
                        break;
                    }
            }
            if !merged {
                result.push(s);
            }
        }
        result
    }
}

impl Default for StructMerger {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn ap(base: &str, offset: i64, size: u8, op: AccessOp) -> AccessPattern {
        AccessPattern::new(base, offset, size, op, 0x1000)
    }

    #[test]
    fn test_access_pattern_display() {
        let a = ap("rdi", 8, 4, AccessOp::Read);
        let s = a.to_string();
        assert!(s.contains("rdi"));
        assert!(s.contains('8'));
    }

    #[test]
    fn test_record_and_recover_basic() {
        let mut r = StructRecovery::new().with_min_accesses(2);
        r.record(ap("rdi", 0, 8, AccessOp::Read));
        r.record(ap("rdi", 8, 4, AccessOp::Write));
        r.record(ap("rdi", 16, 8, AccessOp::Read));
        let structs = r.recover();
        assert_eq!(structs.len(), 1);
        assert_eq!(structs[0].field_count(), 3);
    }

    #[test]
    fn test_recover_skips_single_field() {
        let mut r = StructRecovery::new().with_min_accesses(2);
        r.record(ap("rax", 0, 8, AccessOp::Read));
        let structs = r.recover();
        assert_eq!(structs.len(), 0);
    }

    #[test]
    fn test_field_offset_order() {
        let mut r = StructRecovery::new().with_min_accesses(1);
        r.record(ap("rdi", 16, 4, AccessOp::Read));
        r.record(ap("rdi", 0, 8, AccessOp::Read));
        r.record(ap("rdi", 8, 4, AccessOp::Read));
        let mut structs = r.recover();
        let s = structs.remove(0);
        let offsets: Vec<i64> = s.fields.iter().map(|f| f.offset).collect();
        assert!(offsets.windows(2).all(|w| w[0] < w[1]));
    }

    #[test]
    fn test_field_infer_type_4bytes() {
        let mut f = FieldCandidate::new(0, 4);
        f.infer_type();
        assert_eq!(f.ty, ReconstructedType::Int(32));
    }

    #[test]
    fn test_field_infer_type_8bytes() {
        let mut f = FieldCandidate::new(0, 8);
        f.infer_type();
        assert_eq!(f.ty, ReconstructedType::Int(64));
    }

    #[test]
    fn test_recovered_struct_total_size() {
        let mut s = RecoveredStruct::new("S".into(), vec!["rdi".into()]);
        let mut f1 = FieldCandidate::new(0, 8);
        f1.infer_type();
        let mut f2 = FieldCandidate::new(8, 4);
        f2.infer_type();
        s.add_field(f1);
        s.add_field(f2);
        assert_eq!(s.total_size, 12);
    }

    #[test]
    fn test_recovered_struct_field_at() {
        let mut s = RecoveredStruct::new("S".into(), vec![]);
        let mut f = FieldCandidate::new(16, 4);
        f.infer_type();
        s.add_field(f);
        assert!(s.field_at(16).is_some());
        assert!(s.field_at(0).is_none());
    }

    #[test]
    fn test_recovered_struct_has_gaps() {
        let mut s = RecoveredStruct::new("S".into(), vec![]);
        let mut f1 = FieldCandidate::new(0, 4);
        f1.infer_type();
        let mut f2 = FieldCandidate::new(16, 4); // gap at 4..16
        f2.infer_type();
        s.add_field(f1);
        s.add_field(f2);
        assert!(s.has_gaps());
    }

    #[test]
    fn test_recovered_struct_no_gaps() {
        let mut s = RecoveredStruct::new("S".into(), vec![]);
        let mut f1 = FieldCandidate::new(0, 8);
        f1.infer_type();
        let mut f2 = FieldCandidate::new(8, 4);
        f2.infer_type();
        s.add_field(f1);
        s.add_field(f2);
        assert!(!s.has_gaps());
    }

    #[test]
    fn test_fill_padding() {
        let mut s = RecoveredStruct::new("S".into(), vec![]);
        let mut f1 = FieldCandidate::new(0, 4);
        f1.infer_type();
        let mut f2 = FieldCandidate::new(8, 4); // 4-byte gap
        f2.infer_type();
        s.add_field(f1);
        s.add_field(f2);
        s.fill_padding();
        assert!(!s.has_gaps());
    }

    #[test]
    fn test_to_c_str() {
        let mut s = RecoveredStruct::new("TestStruct".into(), vec![]);
        let mut f = FieldCandidate::new(0, 8);
        f.infer_type();
        s.add_field(f);
        let c = s.to_c_str();
        assert!(c.contains("TestStruct"));
        assert!(c.contains("field_0"));
    }

    #[test]
    fn test_struct_merger_compatible() {
        let merger = StructMerger::new();

        let mut a = RecoveredStruct::new("A".into(), vec!["rdi".into()]);
        let mut fa = FieldCandidate::new(0, 8);
        fa.infer_type();
        a.add_field(fa);
        let mut fa2 = FieldCandidate::new(8, 4);
        fa2.infer_type();
        a.add_field(fa2);

        let mut b = RecoveredStruct::new("B".into(), vec!["rsi".into()]);
        let mut fb = FieldCandidate::new(0, 8);
        fb.infer_type();
        b.add_field(fb);
        let mut fb2 = FieldCandidate::new(8, 4);
        fb2.infer_type();
        b.add_field(fb2);

        let score = merger.compatibility_score(&a, &b);
        assert!(score > 0.9);
    }

    #[test]
    fn test_struct_merger_incompatible() {
        let merger = StructMerger::new();

        let mut a = RecoveredStruct::new("A".into(), vec![]);
        let mut fa = FieldCandidate::new(0, 4);
        fa.infer_type();
        a.add_field(fa);

        let mut b = RecoveredStruct::new("B".into(), vec![]);
        let mut fb = FieldCandidate::new(100, 4);
        fb.infer_type();
        b.add_field(fb);

        let score = merger.compatibility_score(&a, &b);
        assert!(score < 0.1);
    }

    #[test]
    fn test_access_count_for() {
        let mut r = StructRecovery::new();
        r.record(ap("rdi", 0, 4, AccessOp::Read));
        r.record(ap("rdi", 8, 4, AccessOp::Write));
        assert_eq!(r.access_count_for("rdi"), 2);
        assert_eq!(r.access_count_for("rsi"), 0);
    }

    #[test]
    fn test_field_candidate_was_written() {
        let mut r = StructRecovery::new().with_min_accesses(1);
        r.record(ap("rdi", 0, 4, AccessOp::Write));
        r.record(ap("rdi", 8, 4, AccessOp::Read));
        let mut structs = r.recover();
        let s = structs.remove(0);
        let f0 = s.field_at(0).unwrap();
        assert!(f0.was_written);
        let f8 = s.field_at(8).unwrap();
        assert!(!f8.was_written);
    }

    #[test]
    fn test_multi_base_recovery() {
        let mut r = StructRecovery::new().with_min_accesses(2);
        r.record(ap("rdi", 0, 8, AccessOp::Read));
        r.record(ap("rdi", 8, 4, AccessOp::Read));
        r.record(ap("rsi", 0, 8, AccessOp::Write));
        r.record(ap("rsi", 16, 4, AccessOp::Write));
        let structs = r.recover();
        assert_eq!(structs.len(), 2);
    }
}

// ─── OffsetMap ────────────────────────────────────────────────────────────────

/// Maps (base, offset) pairs to their observed access sizes.
#[derive(Debug, Default)]
pub struct OffsetMap {
    inner: std::collections::BTreeMap<(String, i64), u8>,
}

impl OffsetMap {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record(&mut self, base: &str, offset: i64, size: u8) {
        let entry = self.inner.entry((base.to_string(), offset)).or_insert(0);
        *entry = (*entry).max(size);
    }

    #[must_use] 
    pub fn offsets_for(&self, base: &str) -> Vec<(i64, u8)> {
        self.inner
            .range((base.to_string(), i64::MIN)..)
            .take_while(|((b, _), _)| b == base)
            .map(|((_, off), &sz)| (*off, sz))
            .collect()
    }

    #[must_use] 
    pub fn all_bases(&self) -> Vec<String> {
        let mut seen = std::collections::HashSet::new();
        self.inner
            .keys()
            .map(|(b, _)| b.clone())
            .filter(|b| seen.insert(b.clone()))
            .collect()
    }

    #[must_use] 
    pub fn unique_base_count(&self) -> usize {
        self.all_bases().len()
    }
}

// ─── StructLayoutPrinter ─────────────────────────────────────────────────────

/// Pretty-prints a recovered struct layout as a C-like definition.
pub struct StructLayoutPrinter {
    pub show_offsets: bool,
    pub show_access_count: bool,
}

impl Default for StructLayoutPrinter {
    fn default() -> Self {
        Self {
            show_offsets: true,
            show_access_count: false,
        }
    }
}

impl StructLayoutPrinter {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use] 
    pub fn print(&self, s: &RecoveredStruct) -> String {
        let mut out = format!("struct {} {{ // {} bytes\n", s.name, s.total_size);
        for f in &s.fields {
            let offset_part = if self.show_offsets {
                format!("/* +0x{:02x} */", f.offset)
            } else {
                String::new()
            };
            let access_part = if self.show_access_count {
                format!(" // {} access(es)", f.access_count)
            } else {
                String::new()
            };
            writeln!(out, "    {} {:<20} ;{}{}", f.ty.display_name(), f.name, offset_part, access_part).unwrap();
        }
        out.push_str("};\n");
        out
    }

    #[must_use] 
    pub fn print_all(&self, structs: &[RecoveredStruct]) -> String {
        structs
            .iter()
            .map(|s| self.print(s))
            .collect::<Vec<_>>()
            .join("\n")
    }
}

// ─── StructHeuristics ─────────────────────────────────────────────────────────

/// Heuristic analysis of a recovered struct.
pub struct StructHeuristics;

impl StructHeuristics {
    /// True if the struct looks like a linked list node (pointer field at offset 0 or 8).
    #[must_use] 
    pub fn looks_like_list_node(s: &RecoveredStruct) -> bool {
        s.fields
            .iter()
            .any(|f| (f.offset == 0 || f.offset == 8) && f.size == 8)
    }

    /// True if the struct has a vtable pointer (first field is 8-byte pointer).
    #[must_use] 
    pub fn has_vtable_ptr(s: &RecoveredStruct) -> bool {
        s.fields
            .first()
            .is_some_and(|f| f.offset == 0 && f.size == 8)
    }

    /// Estimate struct alignment.
    #[must_use] 
    pub fn alignment(s: &RecoveredStruct) -> u8 {
        s.fields.iter().map(|f| f.size).max().unwrap_or(1)
    }

    /// True if all fields are uniformly sized (e.g. int32 array).
    #[must_use] 
    pub fn is_uniform_array(s: &RecoveredStruct) -> bool {
        let sizes: std::collections::HashSet<u8> = s.fields.iter().map(|f| f.size).collect();
        sizes.len() == 1 && !s.fields.is_empty()
    }
}

// ─── Additional tests ─────────────────────────────────────────────────────────

#[cfg(test)]
mod extra_tests {
    use super::*;
    

    fn _ap(base: &str, offset: i64, size: u8, op: AccessOp) -> AccessPattern {
        AccessPattern::new(base, offset, size, op, 0)
    }

    fn make_struct(fields: &[(i64, u8)]) -> RecoveredStruct {
        let mut s = RecoveredStruct::new("S".into(), vec![]);
        for &(off, sz) in fields {
            let mut f = FieldCandidate::new(off, sz);
            f.infer_type();
            s.add_field(f);
        }
        s
    }

    #[test]
    fn test_offset_map_record_and_get() {
        let mut m = OffsetMap::new();
        m.record("rdi", 0, 8);
        m.record("rdi", 8, 4);
        let offsets = m.offsets_for("rdi");
        assert_eq!(offsets.len(), 2);
    }

    #[test]
    fn test_offset_map_max_size() {
        let mut m = OffsetMap::new();
        m.record("rdi", 0, 4);
        m.record("rdi", 0, 8); // same offset, larger size
        let offsets = m.offsets_for("rdi");
        assert_eq!(offsets[0].1, 8);
    }

    #[test]
    fn test_offset_map_all_bases() {
        let mut m = OffsetMap::new();
        m.record("rdi", 0, 4);
        m.record("rsi", 0, 8);
        m.record("rdi", 8, 4);
        assert_eq!(m.unique_base_count(), 2);
    }

    #[test]
    fn test_struct_layout_printer_basic() {
        let s = make_struct(&[(0, 8), (8, 4)]);
        let p = StructLayoutPrinter::new();
        let out = p.print(&s);
        assert!(out.contains("struct S"));
        assert!(out.contains("field_0"));
    }

    #[test]
    fn test_struct_layout_printer_all() {
        let structs = vec![make_struct(&[(0, 4)]), make_struct(&[(0, 8), (8, 4)])];
        let p = StructLayoutPrinter::new();
        let out = p.print_all(&structs);
        assert!(out.contains("struct S"));
    }

    #[test]
    fn test_struct_heuristics_list_node() {
        let s = make_struct(&[(0, 8), (8, 4)]);
        assert!(StructHeuristics::looks_like_list_node(&s));
    }

    #[test]
    fn test_struct_heuristics_vtable() {
        let s = make_struct(&[(0, 8), (8, 8)]);
        assert!(StructHeuristics::has_vtable_ptr(&s));
    }

    #[test]
    fn test_struct_heuristics_no_vtable() {
        let s = make_struct(&[(0, 4), (4, 4)]);
        assert!(!StructHeuristics::has_vtable_ptr(&s));
    }

    #[test]
    fn test_struct_heuristics_alignment() {
        let s = make_struct(&[(0, 8), (8, 4)]);
        assert_eq!(StructHeuristics::alignment(&s), 8);
    }

    #[test]
    fn test_struct_heuristics_uniform_array() {
        let s = make_struct(&[(0, 4), (4, 4), (8, 4)]);
        assert!(StructHeuristics::is_uniform_array(&s));
    }

    #[test]
    fn test_struct_heuristics_not_uniform() {
        let s = make_struct(&[(0, 4), (4, 8)]);
        assert!(!StructHeuristics::is_uniform_array(&s));
    }

    #[test]
    fn test_struct_recovery_with_offset_map() {
        let mut m = OffsetMap::new();
        m.record("rdi", 0, 8);
        m.record("rdi", 8, 4);
        m.record("rdi", 16, 4);
        m.record("rsi", 0, 4);
        m.record("rsi", 4, 4);

        let mut recovery = StructRecovery::new().with_min_accesses(2);
        for base in m.all_bases() {
            for (off, sz) in m.offsets_for(&base) {
                recovery.record(AccessPattern::new(&base, off, sz, AccessOp::Read, 0));
            }
        }
        let structs = recovery.recover();
        assert_eq!(structs.len(), 2);
    }

    #[test]
    fn test_field_candidate_name_from_offset() {
        let f = FieldCandidate::new(0x18, 4);
        assert_eq!(f.name, "field_18");
    }

    #[test]
    fn test_recovered_struct_c_str_contains_size() {
        let s = make_struct(&[(0, 8), (8, 8)]);
        let c = s.to_c_str();
        assert!(c.contains("0x10") || c.contains("16"));
    }
}
