//! Struct layout recovery for `rustre-analysis-type`.
//!
//! # Overview
//!
//! Struct layout recovery reconstructs the field layout of C structs from
//! binary field-access patterns observed during LLIL analysis.  The pipeline
//! is:
//!
//! ## 1 — Observation
//!
//! Each `[base + offset]` memory access generates a [`FieldAccessPattern`].
//! Patterns are fed to [`StructLayoutRecovery::observe`], which groups them
//! by base pointer variable into [`CandidateStruct`] objects.
//!
//! ## 2 — Resolution
//!
//! [`LayoutSolver::resolve_overlaps`] removes overlapping field candidates,
//! keeping the one with the highest access count (most evidence).
//!
//! ## 3 — Finalisation
//!
//! [`StructLayoutRecovery::finalize`] moves all candidates into the
//! [`TypeDb`], assigning automatic names (`Struct_0`, `Struct_1`, …).
//!
//! ## 4 — Output
//!
//! [`TypeDb::emit_c`] produces a C struct declaration with explicit padding
//! fields for any gaps between recovered fields.
//!
//! # Limitations
//!
//! * The analysis is **intra-procedural** by default.  Use
//!   [`StructMerger::merge_similar`] to combine candidates from multiple
//!   functions that access the same struct through differently-named pointers.
//!
//! * Field types are inferred from access sizes only.  Pointer fields require
//!   additional evidence from type recovery ([`rustre-il-passes`]).
//!
//! * Bit-fields are not recovered; they appear as larger integer fields.
//!
//! # Usage
//!
//! ```rust,ignore
//! let mut rec = StructLayoutRecovery::default();
//! for access in collected_accesses {
//!     rec.observe(&access);
//! }
//! rec.finalize();
//! let c_code = rec.type_db.emit_c("Struct_0").unwrap();
//! println!("{c_code}");
//! ```
//!
//! Recovers struct layouts by analysing field-access patterns:
//! instructions like `[base + offset]` give evidence that `base` points to a
//! struct with a field at `offset`.  [`FieldAccessPattern`] captures each
//! individual observation; [`CandidateStruct`] aggregates patterns for one
//! base variable; [`LayoutSolver`] merges candidates and resolves overlaps;
//! [`PaddingAnalysis`] computes probable padding bytes; and [`TypeDb`] stores
//! the final recovered layouts.

use std::collections::{BTreeMap, HashMap, HashSet};
pub use std::fmt;

// ---------------------------------------------------------------------------
// Well-known struct layout constants
// ---------------------------------------------------------------------------

/// The minimum interesting struct size (2 fields × 1 byte each).
pub const MIN_STRUCT_SIZE: u64 = 2;

/// Common natural alignment values.
pub mod alignment {
    pub const BYTE: u64 = 1;
    pub const WORD: u64 = 2;
    pub const DWORD: u64 = 4;
    pub const QWORD: u64 = 8;
    pub const XMMWORD: u64 = 16;
}

/// Maximum number of fields before a struct is considered suspicious.
pub const MAX_REASONABLE_FIELDS: usize = 256;

// ---------------------------------------------------------------------------
// StructHeuristics — confidence scoring for recovered structs
// ---------------------------------------------------------------------------

/// Assigns a confidence score to a recovered [`CandidateStruct`].
#[derive(Debug, Default)]
pub struct StructHeuristics;

impl StructHeuristics {
    /// Score in [0.0, 1.0].  Higher is more confident.
    #[must_use]
    pub fn score(candidate: &CandidateStruct) -> f64 {
        let fields = candidate.field_count();
        if fields == 0 {
            return 0.0;
        }

        // More fields → higher base confidence.
        let field_score = (f64::from(u32::try_from(fields.min(10)).unwrap_or(u32::MAX)) / 10.0).min(1.0);
        // More observations → higher confidence.
        let obs_score = (f64::from(u32::try_from(candidate.observation_count.min(20)).unwrap_or(u32::MAX)) / 20.0).min(1.0);
        // Penalize very large structs (may be false positives).
        let size_penalty = if candidate.estimated_size() > 4096 {
            0.5
        } else {
            1.0
        };

        // Penalize implausible field counts.
        //
        // `MAX_REASONABLE_FIELDS` was declared and documented as "maximum
        // number of fields before a struct is considered suspicious" — and
        // then consulted NOWHERE. Only byte size was penalised, while
        // `field_score` saturates at ten fields, so a candidate with 5000
        // recovered fields scored **exactly the same as a clean ten-field
        // struct**. A runaway offset scan is the classic way to produce such a
        // candidate, and it looked as trustworthy as a real one.
        let field_penalty = if fields > MAX_REASONABLE_FIELDS {
            0.5
        } else {
            1.0
        };

        (field_score * 0.4 + obs_score * 0.6) * size_penalty * field_penalty
    }

    /// Returns `true` if the candidate meets minimum confidence.
    #[must_use]
    pub fn is_confident(candidate: &CandidateStruct, threshold: f64) -> bool {
        Self::score(candidate) >= threshold
    }
}

// ---------------------------------------------------------------------------
// AccessFrequencyRanker — ranks fields by access frequency
// ---------------------------------------------------------------------------

/// Ranks the fields of a [`CandidateStruct`] by access frequency.
#[derive(Debug, Default)]
pub struct AccessFrequencyRanker;

impl AccessFrequencyRanker {
    /// Return fields sorted by access count (descending).
    #[must_use]
    pub fn ranked_fields(candidate: &CandidateStruct) -> Vec<(u64, &RecoveredField)> {
        let mut fields: Vec<(u64, &RecoveredField)> =
            candidate.fields.iter().map(|(&off, f)| (off, f)).collect();
        fields.sort_by(|a, b| b.1.access_count.cmp(&a.1.access_count));
        fields
    }

    /// Return the offset of the most-accessed field.
    #[must_use]
    pub fn hottest_field_offset(candidate: &CandidateStruct) -> Option<u64> {
        candidate
            .fields
            .values()
            .max_by_key(|f| f.access_count)
            .map(|f| f.offset)
    }
}

// ---------------------------------------------------------------------------
// PointerFieldDetector — marks fields likely to be pointers
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// ADDITIONAL CONSTANTS
// ---------------------------------------------------------------------------

/// Maximum number of fields a recovered struct can have before it is
/// considered a false-positive (e.g. the base pointer was actually an array).
pub const MAX_FIELDS_HEURISTIC: usize = 64;

/// Minimum observation count for a struct to be registered in the database.
pub const MIN_OBSERVATIONS: usize = 2;

/// Common pointer sizes.
pub mod ptr_sizes {
    pub const X86: u64 = 4;
    pub const X64: u64 = 8;
}

/// Default alignment used when no better information is available.
/// In practice this is overridden by the maximum field alignment.
pub const DEFAULT_ALIGNMENT: u64 = 8;

/// Alignment for SIMD registers (128-bit / 16 bytes).
pub const SIMD_ALIGNMENT: u64 = 16;

/// Typical vtable pointer size on x86-64.
pub const VTABLE_PTR_SIZE: u64 = 8;

/// Maximum offset for a field to be considered part of a "header" region
/// (first cache line, offset < 64).
pub const CACHE_LINE_BYTES: u64 = 64;

/// Minimum interesting struct size (must have at least 2 bytes).
pub const MIN_INTERESTING_SIZE: u64 = 2;

/// Maximum allowed struct size before flagging as suspicious.
pub const MAX_TYPICAL_STRUCT_SIZE: u64 = 65_536;

/// Access frequency below which a field is considered "rarely accessed".
pub const RARELY_ACCESSED_THRESHOLD: usize = 2;

// ---------------------------------------------------------------------------
// SizedAccess — a helper pairing an offset with a size
// ---------------------------------------------------------------------------

/// A (offset, size) pair representing a single memory access.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SizedAccess {
    pub offset: u64,
    pub size: u32,
}

impl SizedAccess {
    #[must_use]
    pub const fn new(offset: u64, size: u32) -> Self {
        Self { offset, size }
    }

    #[must_use]
    pub fn end(&self) -> u64 {
        self.offset.saturating_add(u64::from(self.size))
    }
}

impl From<&FieldAccessPattern> for SizedAccess {
    fn from(p: &FieldAccessPattern) -> Self {
        Self::new(p.offset, p.size)
    }
}

impl From<&RecoveredField> for SizedAccess {
    fn from(f: &RecoveredField) -> Self {
        Self::new(f.offset, f.size)
    }
}

// ---------------------------------------------------------------------------
// FieldAccessStats — statistics over a set of patterns
// ---------------------------------------------------------------------------

/// Aggregate statistics for a set of [`FieldAccessPattern`]s.
#[derive(Debug, Clone, Default)]
pub struct FieldAccessStats {
    pub total: usize,
    pub reads: usize,
    pub writes: usize,
    pub unique_bases: usize,
    pub unique_offsets: usize,
}

impl FieldAccessStats {
    /// Compute stats from `patterns`.
    #[must_use] 
    pub fn compute(patterns: &[FieldAccessPattern]) -> Self {
        let reads = patterns.iter().filter(|p| !p.is_write).count();
        let writes = patterns.iter().filter(|p| p.is_write).count();
        let bases: std::collections::HashSet<_> =
            patterns.iter().map(|p| p.base.as_str()).collect();
        let offsets: std::collections::HashSet<u64> = patterns.iter().map(|p| p.offset).collect();
        Self {
            total: patterns.len(),
            reads,
            writes,
            unique_bases: bases.len(),
            unique_offsets: offsets.len(),
        }
    }

    /// Read/write ratio (0.0 if no accesses).
    #[must_use]
    pub fn rw_ratio(&self) -> f64 {
        if self.total == 0 {
            0.0
        } else {
            let reads = u32::try_from(self.reads).unwrap_or(u32::MAX);
            let total = u32::try_from(self.total).unwrap_or(u32::MAX);
            f64::from(reads) / f64::from(total)
        }
    }
}

/// Marks 8-byte fields that are heavily read-only as likely pointer fields.
///
/// A field is considered a pointer candidate if:
/// * Its size is exactly 8 bytes (64-bit pointer width).
/// * It was never written to (read-only access suggests a const pointer or
///   a pointer to configuration data).
///
/// This heuristic produces false positives for `uint64_t` counters that
/// happen to be read-only in the analysed code.  Higher-level analysis
/// (e.g. tracking what is done with the loaded value) would be needed to
/// reduce the false-positive rate.
#[derive(Debug, Default)]
pub struct PointerFieldDetector;

impl PointerFieldDetector {
    /// Return offsets of fields likely to be pointers.
    #[must_use]
    pub fn detect_pointer_fields(candidate: &CandidateStruct) -> Vec<u64> {
        candidate
            .fields
            .iter()
            .filter(|(_, f)| f.size == 8 && !f.ever_written)
            .map(|(&off, _)| off)
            .collect()
    }
}

// ---------------------------------------------------------------------------
// StructDiff — compares two CandidateStructs
// ---------------------------------------------------------------------------

/// Computes the diff between two [`CandidateStruct`]s.
#[derive(Debug, Clone, Default)]
pub struct StructDiff {
    /// Fields in `a` but not `b`.
    pub only_in_a: Vec<u64>,
    /// Fields in `b` but not `a`.
    pub only_in_b: Vec<u64>,
    /// Fields in both but with different sizes.
    pub size_conflict: Vec<u64>,
}

impl StructDiff {
    /// Compute the diff between `a` and `b`.
    #[must_use]
    pub fn compute(a: &CandidateStruct, b: &CandidateStruct) -> Self {
        let mut d = Self::default();
        for (&off, fa) in &a.fields {
            match b.fields.get(&off) {
                None => d.only_in_a.push(off),
                Some(fb) => {
                    if fa.size != fb.size {
                        d.size_conflict.push(off);
                    }
                }
            }
        }
        for &off in b.fields.keys() {
            if !a.fields.contains_key(&off) {
                d.only_in_b.push(off);
            }
        }
        d
    }

    /// True if the structs are identical.
    #[must_use]
    pub const fn is_identical(&self) -> bool {
        self.only_in_a.is_empty() && self.only_in_b.is_empty() && self.size_conflict.is_empty()
    }
}

// ---------------------------------------------------------------------------
// CandidateStructIterator — iterates fields with their computed types
// ---------------------------------------------------------------------------

/// Iterates over fields of a [`CandidateStruct`] with their inferred C types.
pub struct CandidateStructIterator<'a> {
    inner: std::collections::btree_map::Values<'a, u64, RecoveredField>,
}

impl<'a> CandidateStructIterator<'a> {
    /// Create an iterator over the fields of `candidate`.
    #[must_use]
    pub fn new(candidate: &'a CandidateStruct) -> Self {
        Self {
            inner: candidate.fields.values(),
        }
    }
}

impl<'a> Iterator for CandidateStructIterator<'a> {
    type Item = (&'a RecoveredField, String);

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next().map(|f| {
            let ty = FieldTypeClassifier.classify(f).to_owned();
            (f, ty)
        })
    }
}

// ---------------------------------------------------------------------------
// StructSizeEstimator — estimates struct size with alignment
// ---------------------------------------------------------------------------

/// Estimates the natural aligned size of a recovered struct.
#[derive(Debug, Default)]
pub struct StructSizeEstimator;

impl StructSizeEstimator {
    /// Estimate with alignment to the largest field's size.
    #[must_use]
    pub fn estimate(candidate: &CandidateStruct) -> u64 {
        let raw = candidate.estimated_size();
        let max_field_align = candidate
            .fields
            .values()
            .map(|f| u64::from(f.size.min(8)))
            .max()
            .unwrap_or(1);
        PaddingAnalysis::aligned_size(raw, max_field_align)
    }
}

// ---------------------------------------------------------------------------
// FieldRangeChecker — validates field ranges don't exceed struct bounds
// ---------------------------------------------------------------------------

/// Validates that all fields fit within an expected struct size.
#[derive(Debug, Default)]
pub struct FieldRangeChecker;

impl FieldRangeChecker {
    /// Returns fields whose end-offset exceeds `struct_size`.
    #[must_use]
    pub fn out_of_bounds(
        candidate: &CandidateStruct,
        struct_size: u64,
    ) -> Vec<&RecoveredField> {
        candidate
            .fields
            .values()
            .filter(|f| f.end_offset() > struct_size)
            .collect()
    }

    /// True if all fields fit within `struct_size`.
    #[must_use]
    pub fn all_in_bounds(candidate: &CandidateStruct, struct_size: u64) -> bool {
        Self::out_of_bounds(candidate, struct_size).is_empty()
    }
}

// ---------------------------------------------------------------------------
// StructRegistry — global registry of named structs
// ---------------------------------------------------------------------------

/// A global registry mapping struct names to their layouts.
#[derive(Debug, Default)]
pub struct StructRegistry {
    inner: std::collections::BTreeMap<String, CandidateStruct>,
}

impl StructRegistry {
    /// Register a struct.
    pub fn register(&mut self, name: impl Into<String>, candidate: CandidateStruct) {
        self.inner.insert(name.into(), candidate);
    }

    /// Look up a struct.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&CandidateStruct> {
        self.inner.get(name)
    }

    /// All registered struct names.
    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.inner.keys().map(String::as_str)
    }

    /// Number of registered structs.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

// ---------------------------------------------------------------------------
// FieldAccessPattern
// ---------------------------------------------------------------------------

/// A single observed field access `[base + offset]` of `size` bytes.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FieldAccessPattern {
    /// Base pointer variable name.
    pub base: String,
    /// Byte offset from the base.
    pub offset: u64,
    /// Access size in bytes.
    pub size: u32,
    /// Whether this was a write access.
    pub is_write: bool,
    /// Source address of the instruction generating this pattern.
    pub source_addr: u64,
}

impl FieldAccessPattern {
    #[must_use]
    pub fn read(base: impl Into<String>, offset: u64, size: u32, source: u64) -> Self {
        Self {
            base: base.into(),
            offset,
            size,
            is_write: false,
            source_addr: source,
        }
    }

    #[must_use]
    pub fn write(base: impl Into<String>, offset: u64, size: u32, source: u64) -> Self {
        Self {
            base: base.into(),
            offset,
            size,
            is_write: true,
            source_addr: source,
        }
    }

    /// The (exclusive) end offset of this field.
    #[must_use]
    pub fn end_offset(&self) -> u64 {
        self.offset.saturating_add(u64::from(self.size))
    }
}

// ---------------------------------------------------------------------------
// RecoveredField
// ---------------------------------------------------------------------------

/// A recovered field within a candidate struct.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveredField {
    pub offset: u64,
    pub size: u32,
    /// Number of times this field was accessed (confidence).
    pub access_count: usize,
    /// True if the field was written at least once.
    pub ever_written: bool,
    /// Inferred C-like type (e.g. `"uint32_t"`, `"void *"`).
    pub inferred_type: String,
}

impl RecoveredField {
    #[must_use]
    pub fn new(offset: u64, size: u32) -> Self {
        Self {
            offset,
            size,
            access_count: 1,
            ever_written: false,
            inferred_type: guess_type(size),
        }
    }

    #[must_use]
    pub fn end_offset(&self) -> u64 {
        self.offset.saturating_add(u64::from(self.size))
    }
}

fn guess_type(size: u32) -> String {
    match size {
        1 => "uint8_t".into(),
        2 => "uint16_t".into(),
        4 => "uint32_t".into(),
        8 => "uint64_t".into(),
        _ => format!("uint8_t[{size}]"),
    }
}

// ---------------------------------------------------------------------------
// CandidateStruct
// ---------------------------------------------------------------------------

/// Aggregates field accesses observed for a single base pointer and builds a
/// layout from them.
#[derive(Debug, Clone)]
pub struct CandidateStruct {
    pub base_name: String,
    /// Field map: offset → field.
    pub fields: BTreeMap<u64, RecoveredField>,
    /// Access count.
    pub observation_count: usize,
}

impl CandidateStruct {
    #[must_use]
    pub fn new(base_name: impl Into<String>) -> Self {
        Self {
            base_name: base_name.into(),
            fields: BTreeMap::new(),
            observation_count: 0,
        }
    }

    /// Record a field access pattern.
    pub fn observe(&mut self, pat: &FieldAccessPattern) {
        self.observation_count += 1;
        // `RecoveredField::new` already records the access that created the
        // field (`access_count: 1`), so only an EXISTING field gets
        // incremented. Doing both counted the first access to every offset
        // twice, and not even uniformly: two accesses to one offset came to 3
        // inside a single candidate but 4 when observed once in each of two
        // candidates that were later merged — so any threshold on
        // `access_count` depended on how the observations happened to be
        // grouped.
        let is_new = !self.fields.contains_key(&pat.offset);
        let entry = self
            .fields
            .entry(pat.offset)
            .or_insert_with(|| RecoveredField::new(pat.offset, pat.size));
        if !is_new {
            entry.access_count += 1;
        }
        if pat.is_write {
            entry.ever_written = true;
        }
        // Update size if a larger access is seen at the same offset.
        if pat.size > entry.size {
            entry.size = pat.size;
            entry.inferred_type = guess_type(pat.size);
        }
    }

    /// Estimated total struct size (end of last field, with natural alignment).
    #[must_use]
    pub fn estimated_size(&self) -> u64 {
        self.fields
            .values()
            .map(RecoveredField::end_offset)
            .max()
            .unwrap_or(0)
    }

    /// Number of recovered fields.
    #[must_use]
    pub fn field_count(&self) -> usize {
        self.fields.len()
    }

    /// Iterate fields in offset order.
    pub fn fields_ordered(&self) -> impl Iterator<Item = &RecoveredField> {
        self.fields.values()
    }
}

// ---------------------------------------------------------------------------
// LayoutSolver
// ---------------------------------------------------------------------------

/// Resolves overlapping field candidates by choosing the most-observed field
/// when two candidates share an offset range.
#[derive(Debug, Default)]
pub struct LayoutSolver;

impl LayoutSolver {
    /// Resolve any overlapping fields in `candidate` in place.
    pub fn resolve_overlaps(&self, candidate: &mut CandidateStruct) {
        if candidate.fields.len() < 2 {
            return;
        }
        let offsets: Vec<u64> = candidate.fields.keys().copied().collect();
        let mut to_remove: HashSet<u64> = HashSet::new();
        for i in 0..offsets.len() {
            if to_remove.contains(&offsets[i]) {
                continue;
            }
            let field_a = &candidate.fields[&offsets[i]];
            let end_a = field_a.end_offset();
            for j in (i + 1)..offsets.len() {
                if offsets[j] >= end_a {
                    break;
                }
                // offsets[j] overlaps with field_a.
                let cnt_a = field_a.access_count;
                let cnt_b = candidate.fields[&offsets[j]].access_count;
                if cnt_a >= cnt_b {
                    to_remove.insert(offsets[j]);
                } else {
                    to_remove.insert(offsets[i]);
                    break;
                }
            }
        }
        for off in to_remove {
            candidate.fields.remove(&off);
        }
    }

    /// Merge `other` into `base`.
    pub fn merge(&self, base: &mut CandidateStruct, other: &CandidateStruct) {
        base.observation_count += other.observation_count;
        for (off, field) in &other.fields {
            if let Some(entry) = base.fields.get_mut(off) {
                entry.access_count += field.access_count;
                if field.ever_written {
                    entry.ever_written = true;
                }
                if field.size > entry.size {
                    entry.size = field.size;
                    // Take the incoming field's type rather than re-guessing
                    // from size: `guess_type` discarded a more specific type
                    // (e.g. "void *" from pointer detection) carried by the
                    // wider field, and made merge(a,b) != merge(b,a).
                    entry.inferred_type = field.inferred_type.clone();
                } else if field.size == entry.size
                    && entry.inferred_type != field.inferred_type
                {
                    // Same size, conflicting types. Resolve commutatively:
                    // a specific (non size-guessed) type beats the generic
                    // guess; two conflicting specific types pick the
                    // lexicographically smaller so merge order cannot
                    // change the result.
                    let generic = guess_type(entry.size);
                    if entry.inferred_type == generic
                        || (field.inferred_type != generic
                            && field.inferred_type < entry.inferred_type)
                    {
                        entry.inferred_type = field.inferred_type.clone();
                    }
                }
            } else {
                // NOTE: insert the clone as-is; the old
                // `or_insert_with(|| field.clone())` followed by
                // `access_count += field.access_count` double-counted
                // accesses for fields new to `base`, skewing the
                // most-observed-wins overlap resolution.
                base.fields.insert(*off, field.clone());
            }
        }
    }
}

// ---------------------------------------------------------------------------
// PaddingAnalysis
// ---------------------------------------------------------------------------

/// Analyses a recovered layout and identifies probable padding bytes.
#[derive(Debug, Default)]
pub struct PaddingAnalysis;

/// A padding region identified between two fields (or at the end of a struct).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaddingRegion {
    pub start: u64,
    pub size_bytes: u64,
    pub kind: PaddingKind,
}

/// Whether padding is between fields or trailing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaddingKind {
    Between,
    Trailing,
}

impl PaddingAnalysis {
    /// Find padding regions in `candidate`.
    #[must_use] 
    pub fn analyze(&self, candidate: &CandidateStruct, struct_size: u64) -> Vec<PaddingRegion> {
        let mut regions = Vec::new();
        let mut prev_end = 0u64;
        for field in candidate.fields_ordered() {
            if field.offset > prev_end {
                regions.push(PaddingRegion {
                    start: prev_end,
                    size_bytes: field.offset - prev_end,
                    kind: PaddingKind::Between,
                });
            }
            prev_end = field.end_offset();
        }
        // Trailing padding to reach struct_size (aligned to next 4 or 8 bytes).
        if prev_end < struct_size {
            regions.push(PaddingRegion {
                start: prev_end,
                size_bytes: struct_size - prev_end,
                kind: PaddingKind::Trailing,
            });
        }
        regions
    }

    /// Compute the aligned size of a struct for a given alignment.
    #[must_use]
    pub const fn aligned_size(raw_size: u64, alignment: u64) -> u64 {
        if alignment == 0 {
            return raw_size;
        }
        let rem = raw_size % alignment;
        if rem == 0 {
            raw_size
        } else {
            raw_size + alignment - rem
        }
    }
}

// ---------------------------------------------------------------------------
// TypeDb
// ---------------------------------------------------------------------------

/// Database of recovered struct layouts, keyed by an auto-assigned struct name.
#[derive(Debug, Default)]
pub struct TypeDb {
    structs: HashMap<String, CandidateStruct>,
    next_id: u32,
}

impl TypeDb {
    /// Register a recovered [`CandidateStruct`] under a name.
    pub fn register(&mut self, name: impl Into<String>, candidate: CandidateStruct) {
        self.structs.insert(name.into(), candidate);
    }

    /// Auto-name and register a candidate, returning the assigned name.
    pub fn auto_register(&mut self, candidate: CandidateStruct) -> String {
        let name = format!("Struct_{}", self.next_id);
        self.next_id += 1;
        self.structs.insert(name.clone(), candidate);
        name
    }

    /// Look up a struct by name.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&CandidateStruct> {
        self.structs.get(name)
    }

    /// Number of registered structs.
    #[must_use]
    pub fn len(&self) -> usize {
        self.structs.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.structs.is_empty()
    }

    /// Emit a C-like struct declaration for `name`.
    #[must_use]
    pub fn emit_c(&self, name: &str) -> Option<String> {
        use std::fmt::Write as _;
        let candidate = self.structs.get(name)?;
        let mut out = format!("struct {name} {{\n");
        let mut prev_end = 0u64;
        for field in candidate.fields_ordered() {
            if field.offset > prev_end {
                let pad = field.offset - prev_end;
                let _ = writeln!(out, "    uint8_t __pad_0x{prev_end:x}[{pad}];");
            }
            let _ = writeln!(
                out,
                "    {} field_0x{:x};",
                field.inferred_type, field.offset
            );
            prev_end = field.end_offset();
        }
        out.push_str("};\n");
        Some(out)
    }
}

// ---------------------------------------------------------------------------
// StructLayoutRecovery
// ---------------------------------------------------------------------------

/// Top-level struct layout recovery engine.
#[derive(Debug, Default)]
pub struct StructLayoutRecovery {
    solver: LayoutSolver,
    padding: PaddingAnalysis,
    /// Intermediate candidate map: `base_name` → candidate.
    candidates: HashMap<String, CandidateStruct>,
    /// Final type database.
    pub type_db: TypeDb,
}

impl StructLayoutRecovery {
    /// Feed a field-access observation into the engine.
    pub fn observe(&mut self, pat: &FieldAccessPattern) {
        self.candidates
            .entry(pat.base.clone())
            .or_insert_with(|| CandidateStruct::new(pat.base.clone()))
            .observe(pat);
    }

    /// Finalise: resolve overlaps for each candidate and register in [`TypeDb`].
    pub fn finalize(&mut self) {
        // Determinism: `candidates` is a HashMap, and `auto_register` hands
        // out sequential `Struct_N` names — so without sorting, WHICH
        // candidate becomes `Struct_0` vs `Struct_1` followed hash-iteration
        // order (random per run). Register in base-name order.
        let mut candidates: Vec<CandidateStruct> =
            std::mem::take(&mut self.candidates).into_values().collect();
        candidates.sort_by(|a, b| a.base_name.cmp(&b.base_name));
        for mut cand in candidates {
            self.solver.resolve_overlaps(&mut cand);
            self.type_db.auto_register(cand);
        }
    }

    /// Number of candidates seen before finalisation.
    #[must_use]
    pub fn candidate_count(&self) -> usize {
        self.candidates.len()
    }

    /// Access the padding analyzer used by this recovery engine.
    #[must_use]
    pub const fn padding(&self) -> &PaddingAnalysis {
        &self.padding
    }

    /// Mutable access to the padding analyzer.
    pub const fn padding_mut(&mut self) -> &mut PaddingAnalysis {
        &mut self.padding
    }
}

// ---------------------------------------------------------------------------
// StructMerger — merges candidate structs by similarity
// ---------------------------------------------------------------------------

/// Merges candidate structs that share fields with compatible types and
/// offsets.  Useful when the same struct is accessed through different pointer
/// variables.
#[derive(Debug, Default)]
pub struct StructMerger {
    pub merged_pairs: usize,
}

impl StructMerger {
    /// Compute a similarity score between two candidates in [0.0, 1.0].
    #[must_use]
    pub fn similarity(a: &CandidateStruct, b: &CandidateStruct) -> f64 {
        let fields_a: std::collections::HashSet<u64> = a.fields.keys().copied().collect();
        let fields_b: std::collections::HashSet<u64> = b.fields.keys().copied().collect();
        let intersection = fields_a.intersection(&fields_b).count();
        let union = fields_a.union(&fields_b).count();
        if union == 0 {
            0.0
        } else {
            f64::from(u32::try_from(intersection).unwrap_or(u32::MAX))
                / f64::from(u32::try_from(union).unwrap_or(u32::MAX))
        }
    }

    /// Merge all pairs of candidates in `candidates` whose similarity exceeds
    /// `threshold`.  Returns the merged list.
    pub fn merge_similar(
        &mut self,
        mut candidates: Vec<CandidateStruct>,
        threshold: f64,
    ) -> Vec<CandidateStruct> {
        let solver = LayoutSolver;
        let mut merged = vec![false; candidates.len()];
        let mut result = Vec::new();
        for i in 0..candidates.len() {
            if merged[i] {
                continue;
            }
            for j in (i + 1)..candidates.len() {
                if merged[j] {
                    continue;
                }
                let sim = Self::similarity(&candidates[i], &candidates[j]);
                if sim >= threshold {
                    // Merge j into i.
                    let other = candidates[j].clone();
                    solver.merge(&mut candidates[i], &other);
                    merged[j] = true;
                    self.merged_pairs += 1;
                }
            }
            result.push(candidates[i].clone());
        }
        result
    }
}

// ---------------------------------------------------------------------------
// LayoutValidator — validates a recovered layout for consistency
// ---------------------------------------------------------------------------

/// Checks a recovered layout for overlaps and alignment issues.
#[derive(Debug, Default)]
pub struct LayoutValidator;

/// A validation issue found in a layout.
#[derive(Debug, Clone)]
pub struct LayoutIssue {
    pub offset: u64,
    pub description: String,
}

impl LayoutValidator {
    /// Validate `candidate` and return any issues found.
    #[must_use] 
    pub fn validate(&self, candidate: &CandidateStruct) -> Vec<LayoutIssue> {
        let mut issues = Vec::new();
        let mut prev_end = 0u64;
        for field in candidate.fields_ordered() {
            if field.offset < prev_end {
                issues.push(LayoutIssue {
                    offset: field.offset,
                    description: format!(
                        "field at 0x{:x} overlaps with previous (prev_end=0x{:x})",
                        field.offset, prev_end
                    ),
                });
            }
            // Check natural alignment.
            let align = u64::from(field.size.min(8));
            if align > 1 && field.offset % align != 0 {
                issues.push(LayoutIssue {
                    offset: field.offset,
                    description: format!(
                        "field at 0x{:x} (size={}) is misaligned",
                        field.offset, field.size
                    ),
                });
            }
            prev_end = field.end_offset();
        }
        issues
    }

    /// Returns `true` if the layout has no validation issues.
    #[must_use]
    pub fn is_valid(&self, candidate: &CandidateStruct) -> bool {
        self.validate(candidate).is_empty()
    }
}

// ---------------------------------------------------------------------------
// FieldAccessAnalyzer — additional analytics
// ---------------------------------------------------------------------------

/// Analyses a set of field access patterns.
#[derive(Debug, Default)]
pub struct FieldAccessAnalyzer;

impl FieldAccessAnalyzer {
    /// Return all unique offsets in the patterns.
    #[must_use] 
    pub fn unique_offsets(patterns: &[FieldAccessPattern]) -> std::collections::BTreeSet<u64> {
        patterns.iter().map(|p| p.offset).collect()
    }

    /// Return the most frequently accessed offset.
    #[must_use] 
    pub fn hottest_offset(patterns: &[FieldAccessPattern]) -> Option<u64> {
        let mut counts: std::collections::HashMap<u64, usize> = std::collections::HashMap::new();
        for p in patterns {
            *counts.entry(p.offset).or_insert(0) += 1;
        }
        // Deterministic tie-break: highest count, then LOWEST offset. Plain
        // `max_by_key(count)` over a HashMap returns a hash-iteration-order-
        // dependent (nondeterministic) offset when counts tie.
        counts
            .into_iter()
            .max_by_key(|&(off, c)| (c, std::cmp::Reverse(off)))
            .map(|(o, _)| o)
    }

    /// Separate read and write patterns.
    #[must_use] 
    pub fn split_rw(
        patterns: &[FieldAccessPattern],
    ) -> (Vec<&FieldAccessPattern>, Vec<&FieldAccessPattern>) {
        let reads: Vec<_> = patterns.iter().filter(|p| !p.is_write).collect();
        let writes: Vec<_> = patterns.iter().filter(|p| p.is_write).collect();
        (reads, writes)
    }
}

// ---------------------------------------------------------------------------
// CLayoutEmitter — emits complete C struct / typedef declarations
// ---------------------------------------------------------------------------

/// Emits full C layout declarations for all types in a [`TypeDb`].
#[derive(Debug, Default)]
pub struct CLayoutEmitter {
    /// Use `typedef struct { … } Name;` style.
    pub use_typedef: bool,
}

impl CLayoutEmitter {
    /// Emit all structs in `db` as a C header fragment.
    #[must_use] 
    pub fn emit_all(&self, db: &TypeDb) -> String {
        let mut out = String::new();
        // Determinism: `db.structs` is a HashMap; iterating its keys directly
        // would concatenate the emitted structs in a run-dependent order.
        // Emit in a stable (name-sorted) order so the header fragment is
        // reproducible across runs.
        let mut names: Vec<&str> = db.structs.keys().map(String::as_str).collect();
        names.sort_unstable();
        for name in names {
            if let Some(s) = db.emit_c(name) {
                if self.use_typedef {
                    // Wrap as typedef.
                    let typedef = s.replacen(
                        &format!("struct {name} {{"),
                        &format!("typedef struct {name} {{"),
                        1,
                    );
                    let typedef = typedef.replacen("};\n", &format!("}} {name};\n"), 1);
                    out.push_str(&typedef);
                } else {
                    out.push_str(&s);
                }
                out.push('\n');
            }
        }
        out
    }
}

// ---------------------------------------------------------------------------
// StructNameAssigner — auto-names candidates based on access patterns
// ---------------------------------------------------------------------------

/// Assigns human-readable names to anonymous recovered structs.
#[derive(Debug, Default)]
pub struct StructNameAssigner {
    counter: u32,
}

impl StructNameAssigner {
    /// Assign a name based on the base-pointer variable name.
    pub fn assign(&mut self, candidate: &CandidateStruct) -> String {
        let base = &candidate.base_name;
        // Heuristic: if the base name looks like a meaningful variable, use it.
        if base.len() >= 3 && !base.starts_with("tmp") && !base.starts_with("arg") {
            let capitalized = {
                let mut c = base.chars();
                c.next().map_or_else(String::new, |f| {
                    f.to_uppercase().collect::<String>() + c.as_str()
                })
            };
            format!("S_{capitalized}")
        } else {
            let n = self.counter;
            self.counter += 1;
            format!("Struct_{n}")
        }
    }
}

// ---------------------------------------------------------------------------
// FieldTypeClassifier — infers semantic type of a field from access patterns
// ---------------------------------------------------------------------------

/// Adds semantic hints to recovered field types based on access patterns and sizes.
#[derive(Debug, Default)]
pub struct FieldTypeClassifier;

impl FieldTypeClassifier {
    /// Classify `field` based on size and write patterns.
    #[must_use]
    pub const fn classify(&self, field: &RecoveredField) -> &'static str {
        match field.size {
            1 => "uint8_t",
            2 => "uint16_t",
            4 => {
                if field.ever_written {
                    "uint32_t"
                } else {
                    "uint32_t /* ro */"
                }
            }
            8 => "uint64_t",
            16 => "uint8_t[16] /* SIMD */",
            _ => "/* unknown */",
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn read_pat(base: &str, off: u64, sz: u32) -> FieldAccessPattern {
        FieldAccessPattern::read(base, off, sz, 0)
    }

    fn write_pat(base: &str, off: u64, sz: u32) -> FieldAccessPattern {
        FieldAccessPattern::write(base, off, sz, 0)
    }

    // --- FieldAccessPattern ---

    #[test]
    fn field_pattern_end_offset() {
        let p = read_pat("ptr", 8, 4);
        assert_eq!(p.end_offset(), 12);
    }

    /// `hottest_offset` must be deterministic when several offsets tie for the
    /// most accesses. Previously it took `HashMap::into_iter().max_by_key`,
    /// whose tie result follows hash-iteration order (nondeterministic across
    /// runs). Contract: on a tie, the LOWEST offset wins.
    #[test]
    fn hottest_offset_is_deterministic_on_ties() {
        // offsets 8 and 16 both appear twice (tie); offset 24 once.
        let pats = vec![
            read_pat("p", 16, 4),
            read_pat("p", 8, 4),
            read_pat("p", 24, 4),
            read_pat("p", 8, 4),
            read_pat("p", 16, 4),
        ];
        assert_eq!(FieldAccessAnalyzer::hottest_offset(&pats), Some(8));
        // Stable across repeated calls.
        for _ in 0..8 {
            assert_eq!(FieldAccessAnalyzer::hottest_offset(&pats), Some(8));
        }
    }

    #[test]
    fn field_pattern_read_not_write() {
        let p = read_pat("ptr", 0, 8);
        assert!(!p.is_write);
    }

    #[test]
    fn field_pattern_write_flag() {
        let p = write_pat("ptr", 4, 4);
        assert!(p.is_write);
    }

    // --- RecoveredField ---

    #[test]
    fn recovered_field_new() {
        let f = RecoveredField::new(8, 4);
        assert_eq!(f.offset, 8);
        assert_eq!(f.size, 4);
        assert_eq!(f.access_count, 1);
        assert!(!f.ever_written);
    }

    #[test]
    fn guess_type_byte() {
        assert_eq!(guess_type(1), "uint8_t");
    }

    #[test]
    fn guess_type_qword() {
        assert_eq!(guess_type(8), "uint64_t");
    }

    // --- CandidateStruct ---

    #[test]
    fn candidate_observe_adds_field() {
        let mut c = CandidateStruct::new("p");
        c.observe(&read_pat("p", 0, 4));
        assert_eq!(c.field_count(), 1);
    }

    #[test]
    fn candidate_observe_increments_count() {
        let mut c = CandidateStruct::new("p");
        c.observe(&read_pat("p", 0, 4));
        c.observe(&read_pat("p", 0, 4));
        // Two observed accesses are two. This used to assert 3, because
        // `RecoveredField::new` seeded the counter at 1 and `observe`
        // incremented it again for the same access.
        assert_eq!(c.fields[&0].access_count, 2);
    }

    #[test]
    fn candidate_observe_write_sets_flag() {
        let mut c = CandidateStruct::new("p");
        c.observe(&write_pat("p", 4, 8));
        assert!(c.fields[&4].ever_written);
    }

    #[test]
    fn candidate_estimated_size() {
        let mut c = CandidateStruct::new("p");
        c.observe(&read_pat("p", 0, 4));
        c.observe(&read_pat("p", 8, 8));
        assert_eq!(c.estimated_size(), 16);
    }

    #[test]
    fn candidate_empty_size_is_zero() {
        let c = CandidateStruct::new("p");
        assert_eq!(c.estimated_size(), 0);
    }

    #[test]
    fn candidate_multiple_fields() {
        let mut c = CandidateStruct::new("p");
        c.observe(&read_pat("p", 0, 4));
        c.observe(&read_pat("p", 4, 4));
        c.observe(&read_pat("p", 8, 8));
        assert_eq!(c.field_count(), 3);
    }

    // --- LayoutSolver ---

    #[test]
    fn solver_no_overlap_unchanged() {
        let mut c = CandidateStruct::new("p");
        c.observe(&read_pat("p", 0, 4));
        c.observe(&read_pat("p", 8, 4));
        let solver = LayoutSolver;
        solver.resolve_overlaps(&mut c);
        assert_eq!(c.field_count(), 2);
    }

    #[test]
    fn solver_overlap_keeps_more_accessed() {
        let mut c = CandidateStruct::new("p");
        // offset 0, size 8 (covers 0..8)
        c.observe(&read_pat("p", 0, 8));
        c.observe(&read_pat("p", 0, 8)); // access_count = 3
        // offset 4, size 4 (overlaps with 0..8), accessed once
        c.observe(&read_pat("p", 4, 4));
        let solver = LayoutSolver;
        solver.resolve_overlaps(&mut c);
        // offset 0 should win.
        assert!(c.fields.contains_key(&0));
    }

    #[test]
    fn solver_merge_combines_counts() {
        let solver = LayoutSolver;
        let mut a = CandidateStruct::new("p");
        a.observe(&read_pat("p", 0, 4));
        let mut b = CandidateStruct::new("p");
        b.observe(&read_pat("p", 0, 4));
        solver.merge(&mut a, &b);
        assert!(a.fields[&0].access_count > 1);
    }

    // --- PaddingAnalysis ---

    #[test]
    fn padding_no_gap_no_regions() {
        let mut c = CandidateStruct::new("p");
        c.observe(&read_pat("p", 0, 4));
        c.observe(&read_pat("p", 4, 4));
        let pa = PaddingAnalysis;
        let regions = pa.analyze(&c, 8);
        // No gap between 0-4 and 4-8.
        
        assert!(!regions
            .iter().any(|r| r.kind == PaddingKind::Between));
    }

    #[test]
    fn padding_gap_produces_region() {
        let mut c = CandidateStruct::new("p");
        c.observe(&read_pat("p", 0, 4));
        c.observe(&read_pat("p", 8, 4)); // gap at 4..8
        let pa = PaddingAnalysis;
        let regions = pa.analyze(&c, 12);
        assert!(
            regions
                .iter()
                .any(|r| r.kind == PaddingKind::Between && r.start == 4)
        );
    }

    #[test]
    fn padding_trailing_at_end() {
        let mut c = CandidateStruct::new("p");
        c.observe(&read_pat("p", 0, 4));
        let pa = PaddingAnalysis;
        let regions = pa.analyze(&c, 8); // 4 bytes of trailing
        assert!(
            regions
                .iter()
                .any(|r| r.kind == PaddingKind::Trailing && r.start == 4)
        );
    }

    #[test]
    fn padding_aligned_size() {
        assert_eq!(PaddingAnalysis::aligned_size(5, 4), 8);
        assert_eq!(PaddingAnalysis::aligned_size(8, 4), 8);
        assert_eq!(PaddingAnalysis::aligned_size(0, 8), 0);
    }

    // --- TypeDb ---

    #[test]
    fn type_db_register_get() {
        let mut db = TypeDb::default();
        let mut c = CandidateStruct::new("p");
        c.observe(&read_pat("p", 0, 4));
        db.register("MyStruct", c);
        assert!(db.get("MyStruct").is_some());
    }

    #[test]
    fn type_db_auto_register() {
        let mut db = TypeDb::default();
        let c = CandidateStruct::new("p");
        let name = db.auto_register(c);
        assert!(name.starts_with("Struct_"));
        assert_eq!(db.len(), 1);
    }

    #[test]
    fn type_db_emit_c() {
        let mut db = TypeDb::default();
        let mut c = CandidateStruct::new("p");
        c.observe(&read_pat("p", 0, 4));
        c.observe(&read_pat("p", 4, 4));
        db.register("Foo", c);
        let s = db.emit_c("Foo").unwrap();
        assert!(s.contains("struct Foo"));
        assert!(s.contains("field_0x0"));
        assert!(s.contains("field_0x4"));
    }

    #[test]
    fn type_db_emit_c_unknown_returns_none() {
        let db = TypeDb::default();
        assert!(db.emit_c("NoSuchStruct").is_none());
    }

    // --- StructLayoutRecovery ---

    #[test]
    fn recovery_observe_and_finalize() {
        let mut r = StructLayoutRecovery::default();
        r.observe(&read_pat("ptr", 0, 4));
        r.observe(&read_pat("ptr", 4, 4));
        r.finalize();
        assert_eq!(r.type_db.len(), 1);
    }

    #[test]
    fn recovery_two_bases() {
        let mut r = StructLayoutRecovery::default();
        r.observe(&read_pat("p1", 0, 4));
        r.observe(&read_pat("p2", 0, 8));
        r.finalize();
        assert_eq!(r.type_db.len(), 2);
    }

    #[test]
    fn recovery_candidate_count_before_finalize() {
        let mut r = StructLayoutRecovery::default();
        r.observe(&read_pat("a", 0, 4));
        r.observe(&read_pat("b", 0, 4));
        assert_eq!(r.candidate_count(), 2);
    }

    #[test]
    fn recovery_finalize_clears_candidates() {
        let mut r = StructLayoutRecovery::default();
        r.observe(&read_pat("p", 0, 4));
        r.finalize();
        assert_eq!(r.candidate_count(), 0);
    }

    #[test]
    fn recovery_emit_c_after_finalize() {
        let mut r = StructLayoutRecovery::default();
        r.observe(&read_pat("p", 0, 4));
        r.observe(&read_pat("p", 8, 8));
        r.finalize();
        // Find the one registered struct.
        assert_eq!(r.type_db.len(), 1);
    }

    #[test]
    fn recovery_high_frequency_field_survives_overlap() {
        let mut r = StructLayoutRecovery::default();
        // 0..8 accessed 5 times
        for _ in 0..5 {
            r.observe(&read_pat("ptr", 0, 8));
        }
        // 4..8 accessed once — overlap with above
        r.observe(&read_pat("ptr", 4, 4));
        r.finalize();
        let name = "Struct_0";
        let c = r.type_db.get(name).unwrap();
        // offset 0 should survive.
        assert!(c.fields.contains_key(&0));
    }

    // --- Additional FieldAccessPattern tests ---

    #[test]
    fn field_pattern_source_addr_stored() {
        let p = FieldAccessPattern::read("x", 0, 4, 0xABCD);
        assert_eq!(p.source_addr, 0xABCD);
    }

    #[test]
    fn field_pattern_base_name() {
        let p = read_pat("my_ptr", 0, 8);
        assert_eq!(p.base, "my_ptr");
    }

    // --- RecoveredField updates ---

    #[test]
    fn recovered_field_larger_size_wins() {
        let mut c = CandidateStruct::new("p");
        c.observe(&read_pat("p", 0, 1)); // byte
        c.observe(&read_pat("p", 0, 4)); // dword at same offset
        assert_eq!(c.fields[&0].size, 4);
        assert_eq!(c.fields[&0].inferred_type, "uint32_t");
    }

    #[test]
    fn recovered_field_observation_count_increments() {
        let mut c = CandidateStruct::new("p");
        c.observe(&read_pat("p", 0, 4));
        c.observe(&read_pat("p", 0, 4));
        c.observe(&read_pat("p", 0, 4));
        // Three observed accesses are three. (This used to assert 4 while its
        // own comment computed 3 — the assertion had been tuned to whatever
        // the double-increment produced.)
        assert_eq!(c.fields[&0].access_count, 3);
    }

    #[test]
    fn candidate_observation_count() {
        let mut c = CandidateStruct::new("p");
        c.observe(&read_pat("p", 0, 4));
        c.observe(&read_pat("p", 8, 8));
        assert_eq!(c.observation_count, 2);
    }

    // --- guess_type edge cases ---

    #[test]
    fn guess_type_word() {
        assert_eq!(guess_type(2), "uint16_t");
    }

    #[test]
    fn guess_type_dword() {
        assert_eq!(guess_type(4), "uint32_t");
    }

    #[test]
    fn guess_type_unknown_size() {
        let s = guess_type(12);
        assert!(s.contains("[12]"));
    }

    // --- LayoutSolver merge ---

    #[test]
    fn solver_merge_updates_write_flag() {
        let solver = LayoutSolver;
        let mut a = CandidateStruct::new("p");
        a.observe(&read_pat("p", 0, 4));
        let mut b = CandidateStruct::new("p");
        b.observe(&write_pat("p", 0, 4));
        solver.merge(&mut a, &b);
        assert!(a.fields[&0].ever_written);
    }

    /// Regression: merging a field that does not yet exist in `base` must not
    /// double its `access_count` (`or_insert_with(clone)` already carried the
    /// count, then `+=` added it again).
    #[test]
    fn regress_solver_merge_no_double_count_for_new_fields() {
        let solver = LayoutSolver;
        let mut a = CandidateStruct::new("p");
        a.observe(&read_pat("p", 0, 4));
        let mut b = CandidateStruct::new("p");
        b.observe(&read_pat("p", 8, 4)); // offset 8 is new to `a`
        b.observe(&read_pat("p", 8, 4));
        let expected = b.fields[&8].access_count;
        solver.merge(&mut a, &b);
        assert_eq!(
            a.fields[&8].access_count, expected,
            "access_count double-counted on merge of a new field"
        );
    }

    /// Property: for random candidates, merge must preserve
    /// access_count-sum, size-max and ever_written-or per offset.
    #[test]
    fn prop_solver_merge_soundness() {
        use crate::test_prng::xorshift;
        let solver = LayoutSolver;
        let mut state = 0x9E37_79B9_7F4A_7C15u64;
        for _ in 0..200 {
            let mut a = CandidateStruct::new("p");
            let mut b = CandidateStruct::new("p");
            for cand in [&mut a, &mut b] {
                let n = xorshift(&mut state) % 6;
                for _ in 0..n {
                    let off = (xorshift(&mut state) % 5) * 4;
                    let size = 1u32 << (xorshift(&mut state) % 4);
                    let pat = if xorshift(&mut state) % 2 == 0 {
                        FieldAccessPattern::read("p", off, size, 0)
                    } else {
                        FieldAccessPattern::write("p", off, size, 0)
                    };
                    cand.observe(&pat);
                }
            }
            let a_before = a.clone();
            solver.merge(&mut a, &b);
            // Every offset from either input must be present.
            for off in a_before.fields.keys().chain(b.fields.keys()) {
                assert!(a.fields.contains_key(off));
            }
            for (off, f) in &a.fields {
                let fa = a_before.fields.get(off);
                let fb = b.fields.get(off);
                let expect_count = fa.map_or(0, |f| f.access_count)
                    + fb.map_or(0, |f| f.access_count);
                assert_eq!(f.access_count, expect_count, "access_count wrong at {off}");
                let expect_size = fa.map_or(0, |f| f.size).max(fb.map_or(0, |f| f.size));
                assert_eq!(f.size, expect_size, "size wrong at {off}");
                let expect_written = fa.is_some_and(|f| f.ever_written)
                    || fb.is_some_and(|f| f.ever_written);
                assert_eq!(f.ever_written, expect_written, "ever_written wrong at {off}");
            }
            assert_eq!(
                a.observation_count,
                a_before.observation_count + b.observation_count
            );
        }
    }

    // --- PaddingAnalysis edge cases ---

    #[test]
    fn padding_aligned_size_zero_alignment() {
        assert_eq!(PaddingAnalysis::aligned_size(7, 0), 7);
    }

    #[test]
    fn padding_aligned_size_already_aligned() {
        assert_eq!(PaddingAnalysis::aligned_size(16, 8), 16);
    }

    #[test]
    fn padding_empty_candidate_no_regions() {
        let c = CandidateStruct::new("p");
        let pa = PaddingAnalysis;
        let regions = pa.analyze(&c, 0);
        assert!(regions.is_empty());
    }

    // --- TypeDb multiple structs ---

    #[test]
    fn type_db_two_structs() {
        let mut db = TypeDb::default();
        db.auto_register(CandidateStruct::new("a"));
        db.auto_register(CandidateStruct::new("b"));
        assert_eq!(db.len(), 2);
    }

    #[test]
    fn type_db_is_empty_initially() {
        let db = TypeDb::default();
        assert!(db.is_empty());
    }

    #[test]
    fn type_db_not_empty_after_register() {
        let mut db = TypeDb::default();
        db.register("S", CandidateStruct::new("p"));
        assert!(!db.is_empty());
    }

    // --- C emission with padding ---

    #[test]
    fn type_db_emit_c_with_padding() {
        let mut db = TypeDb::default();
        let mut c = CandidateStruct::new("p");
        c.observe(&read_pat("p", 0, 4));
        c.observe(&read_pat("p", 8, 4)); // gap at 4..8
        db.register("Gapped", c);
        let s = db.emit_c("Gapped").unwrap();
        assert!(s.contains("__pad_0x4"));
    }

    // --- StructMerger tests ---

    #[test]
    fn merger_similarity_identical() {
        let mut a = CandidateStruct::new("p");
        a.observe(&read_pat("p", 0, 4));
        a.observe(&read_pat("p", 8, 4));
        let b = a.clone();
        let sim = StructMerger::similarity(&a, &b);
        assert!((sim - 1.0).abs() < 1e-9);
    }

    #[test]
    fn merger_similarity_disjoint() {
        let mut a = CandidateStruct::new("p");
        a.observe(&read_pat("p", 0, 4));
        let mut b = CandidateStruct::new("q");
        b.observe(&read_pat("q", 8, 4));
        let sim = StructMerger::similarity(&a, &b);
        assert!(sim.abs() < 1e-9);
    }

    #[test]
    fn merger_similarity_partial() {
        let mut a = CandidateStruct::new("p");
        a.observe(&read_pat("p", 0, 4));
        a.observe(&read_pat("p", 4, 4));
        let mut b = CandidateStruct::new("q");
        b.observe(&read_pat("q", 0, 4));
        b.observe(&read_pat("q", 8, 4));
        let sim = StructMerger::similarity(&a, &b);
        assert!(sim > 0.0 && sim < 1.0);
    }

    #[test]
    fn merger_merge_similar_combines() {
        let mut a = CandidateStruct::new("p");
        a.observe(&read_pat("p", 0, 4));
        let mut b = CandidateStruct::new("q");
        b.observe(&read_pat("q", 0, 4));
        let mut m = StructMerger::default();
        let merged = m.merge_similar(vec![a, b], 0.5);
        // They share field at offset 0 → should merge into 1.
        assert_eq!(merged.len(), 1);
        assert_eq!(m.merged_pairs, 1);
    }

    // --- LayoutValidator tests ---

    #[test]
    fn validator_valid_layout() {
        let mut c = CandidateStruct::new("p");
        c.observe(&read_pat("p", 0, 4));
        c.observe(&read_pat("p", 4, 4));
        let v = LayoutValidator;
        assert!(v.is_valid(&c));
    }

    #[test]
    fn validator_misaligned_field() {
        let mut c = CandidateStruct::new("p");
        c.observe(&read_pat("p", 1, 4)); // offset 1 is misaligned for 4-byte field
        let v = LayoutValidator;
        let issues = v.validate(&c);
        assert!(!issues.is_empty());
    }

    // --- FieldAccessAnalyzer tests ---

    #[test]
    fn analyzer_unique_offsets() {
        let patterns = vec![
            read_pat("p", 0, 4),
            read_pat("p", 0, 4), // duplicate
            read_pat("p", 8, 4),
        ];
        let offsets = FieldAccessAnalyzer::unique_offsets(&patterns);
        assert_eq!(offsets.len(), 2);
    }

    #[test]
    fn analyzer_hottest_offset() {
        let patterns = vec![
            read_pat("p", 0, 4),
            read_pat("p", 0, 4),
            read_pat("p", 0, 4),
            read_pat("p", 8, 4),
        ];
        let hot = FieldAccessAnalyzer::hottest_offset(&patterns);
        assert_eq!(hot, Some(0));
    }

    #[test]
    fn analyzer_split_rw() {
        let patterns = vec![read_pat("p", 0, 4), write_pat("p", 4, 4)];
        let (reads, writes) = FieldAccessAnalyzer::split_rw(&patterns);
        assert_eq!(reads.len(), 1);
        assert_eq!(writes.len(), 1);
    }

    #[test]
    fn analyzer_empty_hottest_none() {
        let hot = FieldAccessAnalyzer::hottest_offset(&[]);
        assert!(hot.is_none());
    }

    // --- LayoutSolver resolve_overlaps: two fields no overlap ---

    #[test]
    fn solver_two_separate_fields_unchanged() {
        let mut c = CandidateStruct::new("p");
        c.observe(&read_pat("p", 0, 4));
        c.observe(&read_pat("p", 8, 4));
        let solver = LayoutSolver;
        solver.resolve_overlaps(&mut c);
        assert_eq!(c.field_count(), 2);
    }

    // --- CLayoutEmitter tests ---

    #[test]
    fn c_layout_emitter_simple() {
        let mut db = TypeDb::default();
        let mut c = CandidateStruct::new("p");
        c.observe(&read_pat("p", 0, 4));
        db.register("Point", c);
        let emit = CLayoutEmitter { use_typedef: false };
        let s = emit.emit_all(&db);
        assert!(s.contains("struct Point"));
    }

    #[test]
    fn c_layout_emitter_typedef() {
        let mut db = TypeDb::default();
        let mut c = CandidateStruct::new("p");
        c.observe(&read_pat("p", 0, 4));
        db.register("Vec", c);
        let emit = CLayoutEmitter { use_typedef: true };
        let s = emit.emit_all(&db);
        assert!(s.contains("typedef struct Vec"));
    }

    #[test]
    fn c_layout_emitter_empty_db() {
        let db = TypeDb::default();
        let emit = CLayoutEmitter::default();
        assert!(emit.emit_all(&db).is_empty());
    }

    // --- StructNameAssigner tests ---

    #[test]
    fn name_assigner_meaningful_base() {
        let mut a = StructNameAssigner::default();
        let c = CandidateStruct::new("player");
        let name = a.assign(&c);
        assert!(name.contains("Player") || name.starts_with("S_"));
    }

    #[test]
    fn name_assigner_tmp_base_uses_counter() {
        let mut a = StructNameAssigner::default();
        let c = CandidateStruct::new("tmp0");
        let name = a.assign(&c);
        assert!(name.starts_with("Struct_"));
    }

    #[test]
    fn name_assigner_increments() {
        let mut a = StructNameAssigner::default();
        let c1 = CandidateStruct::new("arg0");
        let c2 = CandidateStruct::new("arg1");
        let n1 = a.assign(&c1);
        let n2 = a.assign(&c2);
        assert_ne!(n1, n2);
    }

    // --- FieldTypeClassifier tests ---

    #[test]
    fn field_type_classifier_byte() {
        let f = RecoveredField::new(0, 1);
        let fc = FieldTypeClassifier;
        assert_eq!(fc.classify(&f), "uint8_t");
    }

    #[test]
    fn field_type_classifier_dword_rw() {
        let mut f = RecoveredField::new(0, 4);
        f.ever_written = true;
        let fc = FieldTypeClassifier;
        assert_eq!(fc.classify(&f), "uint32_t");
    }

    #[test]
    fn field_type_classifier_qword() {
        let f = RecoveredField::new(0, 8);
        let fc = FieldTypeClassifier;
        assert_eq!(fc.classify(&f), "uint64_t");
    }

    // --- Multiple observations on same offset ---

    #[test]
    fn candidate_many_observations_single_field() {
        let mut c = CandidateStruct::new("p");
        for _ in 0..100 {
            c.observe(&read_pat("p", 0, 4));
        }
        assert_eq!(c.field_count(), 1);
        assert!(c.fields[&0].access_count >= 100);
    }

    // --- RecoveredField end_offset ---

    #[test]
    fn recovered_field_end_offset_byte() {
        let f = RecoveredField::new(3, 1);
        assert_eq!(f.end_offset(), 4);
    }

    #[test]
    fn recovered_field_end_offset_qword() {
        let f = RecoveredField::new(8, 8);
        assert_eq!(f.end_offset(), 16);
    }

    /// Determinism regression: `CLayoutEmitter::emit_all` concatenates every
    /// struct in a `TypeDb`. The DB keys live in a `HashMap`, so before the fix
    /// the emitted header fragment ordered its structs by `HashMap` iteration
    /// order — a different byte string on different runs. Register many structs
    /// (freshly-seeded `HashMap` per build) and require identical output.
    #[test]
    fn emit_all_is_deterministic() {
        fn build() -> String {
            let mut db = TypeDb::default();
            for i in 0..30u64 {
                let mut c = CandidateStruct::new(format!("s{i}"));
                c.observe(&read_pat("x", 0, 4));
                c.observe(&read_pat("x", 8, 8));
                db.register(format!("Zebra_{i:02}"), c);
            }
            CLayoutEmitter::default().emit_all(&db)
        }
        let base = build();
        for _ in 0..64 {
            assert_eq!(build(), base, "emit_all output is nondeterministic");
        }
        // Sanity: sorted order means Zebra_00 precedes Zebra_29 in the output.
        let p00 = base.find("Zebra_00").expect("has Zebra_00");
        let p29 = base.find("Zebra_29").expect("has Zebra_29");
        assert!(p00 < p29, "structs must be emitted in name-sorted order");
    }

    /// Regression: `finalize` drained a `HashMap`, so WHICH candidate received
    /// each sequential `Struct_N` auto-name was hash-iteration-order random.
    /// Candidates must be registered in base-name order.
    #[test]
    fn regress_finalize_assigns_names_deterministically() {
        fn build() -> Vec<(String, String)> {
            let mut r = StructLayoutRecovery::default();
            for i in 0..30u64 {
                // distinct base names, distinct layouts
                r.observe(&FieldAccessPattern::read(format!("base{i:02}"), i * 4, 4, 0));
            }
            r.finalize();
            (0..30u32)
                .map(|n| {
                    let name = format!("Struct_{n}");
                    let base = r.type_db.get(&name).unwrap().base_name.clone();
                    (name, base)
                })
                .collect()
        }
        let base = build();
        // Sorted registration: Struct_0 belongs to base00, etc.
        assert_eq!(base[0].1, "base00");
        assert_eq!(base[29].1, "base29");
        for _ in 0..32 {
            assert_eq!(build(), base, "finalize name assignment nondeterministic");
        }
    }

    // --- LayoutSolver::merge soundness (property tests) ---

    use crate::test_prng::XorShift64;

    fn random_candidate(rng: &mut XorShift64) -> CandidateStruct {
        let mut c = CandidateStruct::new("p");
        let n = (rng.next() % 6) as usize + 1;
        for _ in 0..n {
            let off = (rng.next() % 8) * 8;
            let size = [1u32, 2, 4, 8][(rng.next() % 4) as usize];
            let mut f = RecoveredField::new(off, size);
            f.access_count = (rng.next() % 5) as usize + 1;
            f.ever_written = rng.next() % 2 == 0;
            if size == 8 && rng.next() % 3 == 0 {
                f.inferred_type = "void *".into(); // simulated pointer detection
            }
            c.fields.insert(off, f);
        }
        c.observation_count = (rng.next() % 4) as usize + 1;
        c
    }

    /// merge(a, b) and merge(b, a) must produce identical field maps —
    /// pointer-detected types must not be lost depending on merge order.
    #[test]
    fn solver_merge_is_commutative() {
        let solver = LayoutSolver;
        let mut rng = XorShift64(0x1234_5678_9abc_def0);
        for round in 0..500 {
            let a = random_candidate(&mut rng);
            let b = random_candidate(&mut rng);
            let mut ab = a.clone();
            solver.merge(&mut ab, &b);
            let mut ba = b.clone();
            solver.merge(&mut ba, &a);
            assert_eq!(ab.fields, ba.fields, "merge not commutative (round {round})");
            assert_eq!(ab.observation_count, ba.observation_count);
        }
    }

    /// Abstract-contains-concrete: after merge, every field present in either
    /// input is present, access counts sum, `ever_written` is OR'd, size is max.
    #[test]
    fn solver_merge_contains_both_inputs() {
        let solver = LayoutSolver;
        let mut rng = XorShift64(0xdead_beef_cafe_f00d);
        for _ in 0..500 {
            let a = random_candidate(&mut rng);
            let b = random_candidate(&mut rng);
            let mut m = a.clone();
            solver.merge(&mut m, &b);
            for (off, fa) in &a.fields {
                let fm = &m.fields[off];
                let fb_count = b.fields.get(off).map_or(0, |f| f.access_count);
                assert_eq!(fm.access_count, fa.access_count + fb_count);
                assert!(fm.size >= fa.size);
                assert!(fm.ever_written || !fa.ever_written);
            }
            for (off, fb) in &b.fields {
                let fm = &m.fields[off];
                assert!(fm.size >= fb.size);
                assert!(fm.ever_written || !fb.ever_written);
            }
            assert_eq!(m.observation_count, a.observation_count + b.observation_count);
        }
    }

    /// Regression: a wider field carrying a specific type (pointer) must keep
    /// that type after merge, not be re-guessed from size.
    #[test]
    fn solver_merge_keeps_specific_type_on_size_growth() {
        let solver = LayoutSolver;
        let mut a = CandidateStruct::new("p");
        a.fields.insert(0, RecoveredField::new(0, 4));
        let mut b = CandidateStruct::new("p");
        let mut ptr_field = RecoveredField::new(0, 8);
        ptr_field.inferred_type = "void *".into();
        b.fields.insert(0, ptr_field);
        solver.merge(&mut a, &b);
        assert_eq!(a.fields[&0].size, 8);
        assert_eq!(a.fields[&0].inferred_type, "void *");
    }

    /// Regression: equal-size merge must not let the generic size-guessed
    /// type overwrite a specific one, in either direction.
    #[test]
    fn solver_merge_specific_type_beats_generic_both_directions() {
        let solver = LayoutSolver;
        let generic = || RecoveredField::new(0, 8);
        let specific = || {
            let mut f = RecoveredField::new(0, 8);
            f.inferred_type = "void *".into();
            f
        };
        let mut a = CandidateStruct::new("p");
        a.fields.insert(0, generic());
        let mut b = CandidateStruct::new("p");
        b.fields.insert(0, specific());
        solver.merge(&mut a, &b);
        assert_eq!(a.fields[&0].inferred_type, "void *");

        let mut c = CandidateStruct::new("p");
        c.fields.insert(0, specific());
        let mut d = CandidateStruct::new("p");
        d.fields.insert(0, generic());
        solver.merge(&mut c, &d);
        assert_eq!(c.fields[&0].inferred_type, "void *");
    }
}

#[cfg(test)]
mod field_count_plausibility {
    use super::*;

    fn candidate_with_fields(n: usize, observations: usize) -> CandidateStruct {
        let mut c = CandidateStruct::new("cand");
        for i in 0..n {
            let off = u64::try_from(i).expect("small index") * 4;
            c.fields.insert(off, RecoveredField::new(off, 4));
        }
        c.observation_count = observations;
        c
    }

    /// An implausible field count must cost confidence.
    ///
    /// `field_score` saturates at ten fields, so before `MAX_REASONABLE_FIELDS`
    /// was actually consulted a candidate with thousands of fields scored
    /// identically to a clean one — the constant existed, was documented as
    /// the suspicion threshold, and was referenced nowhere in the crate.
    #[test]
    fn a_runaway_field_count_scores_below_a_clean_struct() {
        let clean = candidate_with_fields(10, 20);
        let runaway = candidate_with_fields(MAX_REASONABLE_FIELDS + 1, 20);

        let clean_score = StructHeuristics::score(&clean);
        let runaway_score = StructHeuristics::score(&runaway);

        assert!(
            runaway_score < clean_score,
            "a {}-field candidate must not score like a 10-field one ({runaway_score} vs {clean_score})",
            MAX_REASONABLE_FIELDS + 1
        );
    }

    /// Positive control: the penalty must not fire on ordinary structs, or the
    /// test above could be satisfied by penalising everything.
    #[test]
    fn ordinary_field_counts_are_not_penalised() {
        let small = candidate_with_fields(4, 20);
        // `field_score` saturates at ten fields, so a saturated-but-reasonable
        // candidate is the right comparison for the threshold: any difference
        // between these two can only come from the new field penalty.
        let saturated = candidate_with_fields(10, 20);
        let at_limit = candidate_with_fields(MAX_REASONABLE_FIELDS, 20);
        let over = candidate_with_fields(MAX_REASONABLE_FIELDS + 1, 20);

        assert!(
            (StructHeuristics::score(&at_limit) - StructHeuristics::score(&saturated)).abs() < 1e-9,
            "the threshold is exclusive: exactly MAX_REASONABLE_FIELDS is still reasonable"
        );
        assert!(
            StructHeuristics::score(&over) < StructHeuristics::score(&at_limit),
            "one field past the threshold must cost something"
        );
        assert!(
            StructHeuristics::score(&small) > 0.0,
            "an ordinary struct must still score above zero"
        );
    }
}
