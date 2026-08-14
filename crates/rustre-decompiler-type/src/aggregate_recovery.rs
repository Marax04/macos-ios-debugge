// aggregate_recovery.rs — Recover aggregate (struct/union) types from field-access patterns.
//
// This module analyses the set of field accesses observed for each variable and
// synthesises a best-fit aggregate layout.  It is deliberately independent of
// the lattice solver in `type_flow_lattice` so that the two analyses can be
// composed in either order.

use std::collections::{BTreeMap, HashMap, HashSet};

use serde::{Deserialize, Serialize};

use crate::{DecompType, StructField, StructType};

// ────────────────────────────────────────────────────────────────────────────
// Field-access evidence
// ────────────────────────────────────────────────────────────────────────────

/// A single observed memory access that hints at a struct field.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FieldAccess {
    /// The variable (SSA name or register id) used as the base pointer.
    pub base_var: u32,
    /// Byte offset from the base pointer.
    pub offset: i64,
    /// Width of the access in bytes (1, 2, 4, 8, …).
    pub access_bytes: u32,
    /// Whether the access was a read (`true`) or a write (`false`).
    pub is_read: bool,
    /// Optional type hint derived from surrounding context (e.g. from a known
    /// API call parameter type).
    pub type_hint: Option<DecompType>,
    /// Address in the binary where the access was observed.
    pub site_addr: u64,
}

impl FieldAccess {
    /// Create a plain read access with no type hint.
    #[must_use]
    pub const fn read(base_var: u32, offset: i64, access_bytes: u32, site_addr: u64) -> Self {
        Self {
            base_var,
            offset,
            access_bytes,
            is_read: true,
            type_hint: None,
            site_addr,
        }
    }

    /// Create a plain write access with no type hint.
    #[must_use]
    pub const fn write(base_var: u32, offset: i64, access_bytes: u32, site_addr: u64) -> Self {
        Self {
            base_var,
            offset,
            access_bytes,
            is_read: false,
            type_hint: None,
            site_addr,
        }
    }

    /// Attach a type hint and return `self` (builder style).
    #[must_use]
    pub fn with_hint(mut self, hint: DecompType) -> Self {
        self.type_hint = Some(hint);
        self
    }

    /// The exclusive end offset of this access.
    #[must_use]
    pub fn end_offset(&self) -> i64 {
        self.offset + i64::from(self.access_bytes)
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Recovered struct
// ────────────────────────────────────────────────────────────────────────────

/// One field inferred for a recovered aggregate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveredField {
    /// Byte offset within the aggregate.
    pub offset: i64,
    /// Inferred size in bytes.
    pub size_bytes: u32,
    /// Inferred type (may be Unknown if no hint was available).
    pub field_type: DecompType,
    /// Human-readable name derived from offset and access count.
    pub name: String,
    /// Number of distinct access sites that contributed to this field.
    pub access_count: usize,
    /// True when any access to this field was a write.
    pub written: bool,
}

impl RecoveredField {
    fn from_accesses(offset: i64, accesses: &[&FieldAccess]) -> Self {
        let size_bytes = accesses
            .iter()
            .map(|a| a.access_bytes)
            .max()
            .unwrap_or(1);

        // Pick the best type hint: prefer an explicit hint, else derive from size.
        let field_type = accesses
            .iter()
            .find_map(|a| a.type_hint.clone())
            .unwrap_or(match size_bytes {
                1 => DecompType::Int(rustre_decompiler_expr::IntWidth::U8),
                2 => DecompType::Int(rustre_decompiler_expr::IntWidth::U16),
                4 => DecompType::Int(rustre_decompiler_expr::IntWidth::U32),
                _ => DecompType::Int(rustre_decompiler_expr::IntWidth::U64),
            });

        let written = accesses.iter().any(|a| !a.is_read);
        let access_count = accesses.len();
        let name = format!("field_{:04x}", u32::try_from(offset).unwrap_or(u32::MAX));

        Self {
            offset,
            size_bytes,
            field_type,
            name,
            access_count,
            written,
        }
    }

    /// Convert into the canonical `StructField` used by the rest of the
    /// decompiler pipeline.
    #[must_use]
    pub fn to_struct_field(&self) -> StructField {
        StructField {
            name: self.name.clone(),
            offset: self.offset.cast_unsigned(),
            ty: self.field_type.clone(),
        }
    }
}

/// The result of recovering one aggregate type for a given base variable.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveredStruct {
    /// The base variable this struct was recovered for.
    pub base_var: u32,
    /// Sorted list of recovered fields.
    pub fields: Vec<RecoveredField>,
    /// Total inferred size of the aggregate in bytes.
    pub total_size: u32,
    /// Confidence score in [0.0, 1.0].
    pub confidence: f64,
    /// Suggested name (``struct_<base_var>``).
    pub name: String,
}

impl RecoveredStruct {
    /// Emit a `StructType` compatible with the rest of the crate.
    #[must_use]
    pub fn to_struct_type(&self) -> StructType {
        let fields: Vec<StructField> = self.fields.iter().map(RecoveredField::to_struct_field).collect();
        StructType {
            name: self.name.clone(),
            fields,
            total_size: u64::from(self.total_size),
        }
    }

    /// True when there are no overlapping field ranges (a basic sanity check).
    #[must_use]
    pub fn is_consistent(&self) -> bool {
        let mut end: i64 = i64::MIN;
        for f in &self.fields {
            if f.offset < end {
                return false;
            }
            end = f.offset + i64::from(f.size_bytes);
        }
        true
    }

    /// Iterate over gaps (padding regions) between accessed fields.
    ///
    /// Synthetic padding fields inserted by the layout solver (those with
    /// `access_count == 0`) are skipped, so a gap between two genuinely
    /// observed fields is still reported even if it was filled with a
    /// `_pad_*` placeholder.
    #[must_use]
    pub fn gaps(&self) -> Vec<(i64, u32)> {
        let mut result = Vec::new();
        let mut cursor: i64 = 0;
        for f in &self.fields {
            if f.access_count == 0 {
                // Synthetic padding — does not close a gap.
                continue;
            }
            if f.offset > cursor {
                result.push((cursor, u32::try_from(f.offset - cursor).unwrap_or(u32::MAX)));
            }
            cursor = f.offset + i64::from(f.size_bytes);
        }
        result
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Layout solver
// ────────────────────────────────────────────────────────────────────────────

/// Options that control how the layout solver handles conflicts and padding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LayoutSolverConfig {
    /// When two accesses overlap, keep the wider one.
    pub prefer_wider_on_overlap: bool,
    /// Insert explicit padding fields for gaps ≥ this many bytes.
    pub min_gap_for_padding: u32,
    /// Maximum struct size; accesses beyond this offset are dropped.
    pub max_struct_bytes: u32,
    /// Whether to align each field to its natural alignment.
    pub enforce_natural_alignment: bool,
}

impl Default for LayoutSolverConfig {
    fn default() -> Self {
        Self {
            prefer_wider_on_overlap: true,
            min_gap_for_padding: 1,
            max_struct_bytes: 0x10000,
            enforce_natural_alignment: true,
        }
    }
}

/// Errors that can occur during layout solving.
#[derive(Debug, Clone, thiserror::Error, Serialize, Deserialize)]
pub enum LayoutError {
    #[error("irresolvable overlap at offset {0}: bytes {1} and {2}")]
    IrresolvableOverlap(i64, u32, u32),
    #[error("struct too large: {0} bytes exceeds limit {1}")]
    TooLarge(u32, u32),
    #[error("type error during layout: {0}")]
    Type(String),
}

/// Solves the set of field accesses for one base variable into a `RecoveredStruct`.
pub struct LayoutSolver {
    config: LayoutSolverConfig,
}

impl LayoutSolver {
    #[must_use]
    pub const fn new(config: LayoutSolverConfig) -> Self {
        Self { config }
    }

    #[must_use]
    pub fn with_defaults() -> Self {
        Self {
            config: LayoutSolverConfig::default(),
        }
    }

    /// Run the solver on the collected accesses and return a `RecoveredStruct`.
    ///
    /// # Errors
    ///
    /// Returns [`LayoutError`] if overlapping fields cannot be resolved or the
    /// struct size exceeds `config.max_struct_bytes`.
    pub fn solve(
        &self,
        base_var: u32,
        accesses: &[FieldAccess],
    ) -> Result<RecoveredStruct, LayoutError> {
        // Group by offset.
        let mut by_offset: BTreeMap<i64, Vec<&FieldAccess>> = BTreeMap::new();
        for a in accesses {
            if a.offset < 0
                || a.end_offset() > i64::from(self.config.max_struct_bytes)
            {
                continue;
            }
            by_offset.entry(a.offset).or_default().push(a);
        }

        // Resolve overlaps.
        let resolved = self.resolve_overlaps(by_offset)?;

        // Build fields.
        let mut fields: Vec<RecoveredField> = resolved
            .iter()
            .map(|(&off, acc)| RecoveredField::from_accesses(off, acc))
            .collect();
        fields.sort_by_key(|f| f.offset);

        // Insert padding fields where requested.
        if self.config.min_gap_for_padding > 0 {
            fields = self.insert_padding(&fields);
        }

        // Compute total size.
        // Use checked arithmetic: if the last field's end offset overflows u32 it
        // means the struct is larger than any real u32 address space, which the
        // TooLarge check below will catch after we clamp to u32::MAX.
        let total_size = fields
            .last()
            .map_or(0, |f| {
                let end = f.offset.saturating_add(i64::from(f.size_bytes));
                u32::try_from(end).unwrap_or(u32::MAX)
            });

        if total_size > self.config.max_struct_bytes {
            return Err(LayoutError::TooLarge(
                total_size,
                self.config.max_struct_bytes,
            ));
        }

        let confidence = Self::compute_confidence(&fields, accesses);
        let name = format!("struct_{base_var}");

        Ok(RecoveredStruct {
            base_var,
            fields,
            total_size,
            confidence,
            name,
        })
    }

    fn resolve_overlaps<'a>(
        &self,
        by_offset: BTreeMap<i64, Vec<&'a FieldAccess>>,
    ) -> Result<BTreeMap<i64, Vec<&'a FieldAccess>>, LayoutError> {
        let mut result: BTreeMap<i64, Vec<&'a FieldAccess>> = BTreeMap::new();
        let mut last_end: i64 = i64::MIN;

        for (offset, accesses) in by_offset {
            // Find max size at this offset.
            let max_size = accesses.iter().map(|a| a.access_bytes).max().unwrap_or(1);
            let end = offset + i64::from(max_size);

            if offset < last_end {
                if self.config.prefer_wider_on_overlap {
                    // Attempt merge: keep only those that start at `offset`.
                    // The previous field already covers this region; skip.
                    continue;
                }
                let prev_size = result
                    .values()
                    .last()
                    .and_then(|v| v.first())
                    .map_or(1, |a| a.access_bytes);
                return Err(LayoutError::IrresolvableOverlap(
                    offset,
                    prev_size,
                    max_size,
                ));
            }

            result.insert(offset, accesses);
            last_end = end;
        }

        Ok(result)
    }

    fn insert_padding(&self, fields: &[RecoveredField]) -> Vec<RecoveredField> {
        let mut out: Vec<RecoveredField> = Vec::with_capacity(fields.len() * 2);
        let mut cursor: i64 = 0;
        for f in fields {
            let gap = f.offset - cursor;
            if gap >= i64::from(self.config.min_gap_for_padding) {
                // Clamp gap to u32 range; if it exceeds u32::MAX the struct is
                // already larger than the TooLarge check allows, so saturating
                // is safe here (the outer check will reject it).
                let gap_u32 = u32::try_from(gap).unwrap_or(u32::MAX);
                out.push(RecoveredField {
                    offset: cursor,
                    size_bytes: gap_u32,
                    field_type: DecompType::Array(
                        Box::new(DecompType::Int(rustre_decompiler_expr::IntWidth::U8)),
                        gap.cast_unsigned(),
                    ),
                    name: format!("_pad_{:04x}", u32::try_from(cursor).unwrap_or(u32::MAX)),
                    access_count: 0,
                    written: false,
                });
            }
            cursor = f.offset + i64::from(f.size_bytes);
            out.push(f.clone());
        }
        out
    }

    fn compute_confidence(fields: &[RecoveredField], accesses: &[FieldAccess]) -> f64 {
        if accesses.is_empty() {
            return 0.0;
        }
        // Confidence rises with the number of multi-accessed fields and falls
        // with the number of padding regions.
        let multi_accessed = fields.iter().filter(|f| f.access_count > 1).count();
        let padded = fields.iter().filter(|f| f.access_count == 0).count();
        let total = fields.len().max(1);
        let f64_of = |n: usize| f64::from(u32::try_from(n.min(u32::MAX as usize)).unwrap_or(u32::MAX));
        let base = (f64_of(multi_accessed) + 1.0) / (f64_of(total) + f64_of(padded) + 1.0);
        base.clamp(0.0, 1.0)
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Aggregate recovery engine
// ────────────────────────────────────────────────────────────────────────────

/// Collects field accesses per base variable and drives the layout solver.
pub struct AggregateRecovery {
    solver: LayoutSolver,
    accesses: HashMap<u32, Vec<FieldAccess>>,
}

impl AggregateRecovery {
    #[must_use]
    pub fn new(config: LayoutSolverConfig) -> Self {
        Self {
            solver: LayoutSolver::new(config),
            accesses: HashMap::new(),
        }
    }

    #[must_use]
    pub fn with_defaults() -> Self {
        Self::new(LayoutSolverConfig::default())
    }

    /// Record a single field access.
    pub fn record(&mut self, access: FieldAccess) {
        self.accesses.entry(access.base_var).or_default().push(access);
    }

    /// Record a batch of accesses.
    pub fn record_many(&mut self, accesses: impl IntoIterator<Item = FieldAccess>) {
        for a in accesses {
            self.record(a);
        }
    }

    /// Number of distinct base variables seen.
    #[must_use]
    pub fn variable_count(&self) -> usize {
        self.accesses.len()
    }

    /// Solve all collected variables and return results.
    #[must_use]
    pub fn solve_all(&self) -> RecoveryResults {
        let mut recovered: Vec<RecoveredStruct> = Vec::new();
        let mut errors: Vec<(u32, LayoutError)> = Vec::new();

        let mut vars: Vec<u32> = self.accesses.keys().copied().collect();
        vars.sort_unstable();

        for var in vars {
            let accesses = &self.accesses[&var];
            match self.solver.solve(var, accesses) {
                Ok(s) => recovered.push(s),
                Err(e) => errors.push((var, e)),
            }
        }

        RecoveryResults { recovered, errors }
    }

    /// Solve only the specified variable.
    ///
    /// # Errors
    ///
    /// Returns [`LayoutError`] if overlapping fields cannot be resolved or the
    /// struct size exceeds the configured maximum.
    pub fn solve_var(&self, base_var: u32) -> Result<RecoveredStruct, LayoutError> {
        let accesses = self
            .accesses
            .get(&base_var)
            .map_or(&[] as &[FieldAccess], Vec::as_slice);
        self.solver.solve(base_var, accesses)
    }

    /// Return the raw accesses for a variable.
    #[must_use]
    pub fn accesses_for(&self, base_var: u32) -> &[FieldAccess] {
        self.accesses.get(&base_var).map_or(&[], Vec::as_slice)
    }
}

/// The output of solving all variables.
#[derive(Debug, Serialize, Deserialize)]
pub struct RecoveryResults {
    pub recovered: Vec<RecoveredStruct>,
    pub errors: Vec<(u32, LayoutError)>,
}

impl RecoveryResults {
    /// Iterate only over structs that meet a minimum confidence threshold.
    #[must_use = "iterator is lazy; consume it to get results"]
    pub fn confident(&self, min_confidence: f64) -> impl Iterator<Item = &RecoveredStruct> {
        self.recovered
            .iter()
            .filter(move |s| s.confidence >= min_confidence)
    }

    /// Collect all recovered structs into a map keyed by base variable.
    #[must_use]
    pub fn as_map(&self) -> HashMap<u32, &RecoveredStruct> {
        self.recovered.iter().map(|s| (s.base_var, s)).collect()
    }

    /// Convert all recovered structs to `StructType` for use in the type registry.
    #[must_use]
    pub fn to_struct_types(&self) -> Vec<StructType> {
        self.recovered.iter().map(RecoveredStruct::to_struct_type).collect()
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Alias analysis helper: detect when two variables alias the same struct
// ────────────────────────────────────────────────────────────────────────────

/// Lightweight alias set: groups variables that appear to point to the same
/// allocation / struct type based on structural similarity of their access
/// patterns.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct AliasGroups {
    /// Each inner vec is a group of aliasing base variables.
    pub groups: Vec<Vec<u32>>,
}

impl AliasGroups {
    /// Compute alias groups from `RecoveryResults` by comparing field sets.
    /// Two variables are considered potential aliases when their recovered
    /// field offset/size pairs are identical.
    #[must_use] 
    pub fn from_results(results: &RecoveryResults) -> Self {
        // Map from fingerprint → list of base_vars.
        let mut by_fingerprint: HashMap<Vec<(i64, u32)>, Vec<u32>> = HashMap::new();
        for s in &results.recovered {
            let fp: Vec<(i64, u32)> = s
                .fields
                .iter()
                .filter(|f| f.access_count > 0)
                .map(|f| (f.offset, f.size_bytes))
                .collect();
            by_fingerprint.entry(fp).or_default().push(s.base_var);
        }

        let groups: Vec<Vec<u32>> = by_fingerprint
            .into_values()
            .filter(|g| g.len() > 1)
            .collect();

        Self { groups }
    }

    /// Return the group index that contains `var`, if any.
    #[must_use]
    pub fn group_of(&self, var: u32) -> Option<usize> {
        self.groups
            .iter()
            .position(|g| g.contains(&var))
    }

    /// True when two variables are in the same alias group.
    #[must_use]
    pub fn may_alias(&self, a: u32, b: u32) -> bool {
        if let (Some(ga), Some(gb)) = (self.group_of(a), self.group_of(b)) {
            return ga == gb;
        }
        false
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Field access statistics
// ────────────────────────────────────────────────────────────────────────────

/// Summary statistics for the accesses of one base variable.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessStats {
    pub base_var: u32,
    pub total_accesses: usize,
    pub unique_offsets: usize,
    pub read_count: usize,
    pub write_count: usize,
    pub min_offset: i64,
    pub max_offset: i64,
    pub hinted_count: usize,
}

impl AccessStats {
    #[must_use]
    pub fn compute(base_var: u32, accesses: &[FieldAccess]) -> Self {
        let offsets: HashSet<i64> = accesses.iter().map(|a| a.offset).collect();
        let read_count = accesses.iter().filter(|a| a.is_read).count();
        let write_count = accesses.len() - read_count;
        let min_offset = accesses.iter().map(|a| a.offset).min().unwrap_or(0);
        let max_offset = accesses.iter().map(|a| a.offset).max().unwrap_or(0);
        let hinted_count = accesses.iter().filter(|a| a.type_hint.is_some()).count();

        Self {
            base_var,
            total_accesses: accesses.len(),
            unique_offsets: offsets.len(),
            read_count,
            write_count,
            min_offset,
            max_offset,
            hinted_count,
        }
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Tests
// ────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_accesses() -> Vec<FieldAccess> {
        vec![
            FieldAccess::read(1, 0, 4, 0x1000),
            FieldAccess::read(1, 4, 4, 0x1004),
            FieldAccess::write(1, 8, 8, 0x1008),
            FieldAccess::read(1, 16, 2, 0x1010),
            FieldAccess::read(1, 18, 2, 0x1012),
        ]
    }

    #[test]
    fn solve_basic_struct() {
        let mut rec = AggregateRecovery::with_defaults();
        rec.record_many(make_accesses());

        let results = rec.solve_all();
        assert!(results.errors.is_empty());
        assert_eq!(results.recovered.len(), 1);

        let s = &results.recovered[0];
        assert_eq!(s.base_var, 1);
        assert!(s.total_size > 0);
        assert!(s.is_consistent());
    }

    #[test]
    fn field_names_derive_from_offset() {
        let solver = LayoutSolver::with_defaults();
        let accesses = make_accesses();
        let s = solver.solve(1, &accesses).unwrap();
        for f in &s.fields {
            if f.access_count > 0 {
                assert!(f.name.starts_with("field_"), "bad name: {}", f.name);
            }
        }
    }

    #[test]
    fn gaps_identified() {
        let mut rec = AggregateRecovery::with_defaults();
        rec.record(FieldAccess::read(2, 0, 4, 0x2000));
        rec.record(FieldAccess::read(2, 12, 4, 0x2010));
        let results = rec.solve_all();
        let s = &results.recovered[0];
        assert!(!s.gaps().is_empty(), "expected gap between offset 4 and 12");
    }

    #[test]
    fn alias_groups_same_layout() {
        let mut rec = AggregateRecovery::with_defaults();
        for var in [10u32, 11u32] {
            rec.record(FieldAccess::read(var, 0, 4, 0x3000));
            rec.record(FieldAccess::read(var, 4, 4, 0x3004));
        }
        let results = rec.solve_all();
        let aliases = AliasGroups::from_results(&results);
        assert!(aliases.may_alias(10, 11));
    }

    #[test]
    fn access_stats_correct() {
        let accesses = make_accesses();
        let stats = AccessStats::compute(1, &accesses);
        assert_eq!(stats.total_accesses, 5);
        assert_eq!(stats.read_count, 4);
        assert_eq!(stats.write_count, 1);
    }

    #[test]
    fn to_struct_type_roundtrip() {
        let mut rec = AggregateRecovery::with_defaults();
        rec.record_many(make_accesses());
        let results = rec.solve_all();
        let types = results.to_struct_types();
        assert!(!types.is_empty());
        assert!(!types[0].fields.is_empty());
    }

    // ── Added comprehensive tests ─────────────────────────────────────────────

    #[test]
    fn empty_accesses_produce_empty_struct() {
        let solver = LayoutSolver::with_defaults();
        let s = solver.solve(42, &[]).unwrap();
        assert_eq!(s.base_var, 42);
        assert_eq!(s.total_size, 0);
        assert!(s.fields.is_empty());
        assert_eq!(s.confidence, 0.0);
        assert!(s.is_consistent());
        assert!(s.gaps().is_empty());
    }

    #[test]
    fn negative_offsets_dropped() {
        let solver = LayoutSolver::with_defaults();
        let accesses = vec![
            FieldAccess::read(1, -8, 4, 0x1000),
            FieldAccess::read(1, 0, 4, 0x1004),
        ];
        let s = solver.solve(1, &accesses).unwrap();
        // Only the non-negative offset should appear.
        assert!(s.fields.iter().filter(|f| f.access_count > 0).count() == 1);
    }

    #[test]
    fn out_of_bounds_offsets_dropped() {
        let mut cfg = LayoutSolverConfig::default();
        cfg.max_struct_bytes = 32;
        let solver = LayoutSolver::new(cfg);
        let accesses = vec![
            FieldAccess::read(1, 0, 4, 0x1000),
            FieldAccess::read(1, 100, 4, 0x1004), // beyond max_struct_bytes
        ];
        let s = solver.solve(1, &accesses).unwrap();
        assert!(s.total_size <= 32);
        assert_eq!(s.fields.iter().filter(|f| f.access_count > 0).count(), 1);
    }

    #[test]
    fn overlapping_accesses_resolved_when_preferred() {
        let mut cfg = LayoutSolverConfig::default();
        cfg.prefer_wider_on_overlap = true;
        cfg.min_gap_for_padding = 0;
        let solver = LayoutSolver::new(cfg);
        // Two accesses overlap at 0..8 and 4..6.
        let accesses = vec![
            FieldAccess::read(1, 0, 8, 0x1000),
            FieldAccess::read(1, 4, 2, 0x1004),
        ];
        let s = solver.solve(1, &accesses).unwrap();
        // The wider access wins; the inner overlapping access is dropped.
        let real_fields: Vec<_> = s.fields.iter().filter(|f| f.access_count > 0).collect();
        assert_eq!(real_fields.len(), 1);
        assert_eq!(real_fields[0].size_bytes, 8);
        assert!(s.is_consistent());
    }

    #[test]
    fn overlapping_accesses_error_when_strict() {
        let mut cfg = LayoutSolverConfig::default();
        cfg.prefer_wider_on_overlap = false;
        let solver = LayoutSolver::new(cfg);
        let accesses = vec![
            FieldAccess::read(1, 0, 8, 0x1000),
            FieldAccess::read(1, 4, 2, 0x1004),
        ];
        let err = solver.solve(1, &accesses).unwrap_err();
        assert!(matches!(err, LayoutError::IrresolvableOverlap(..)));
    }

    #[test]
    fn padding_inserted_for_gap() {
        let mut cfg = LayoutSolverConfig::default();
        cfg.min_gap_for_padding = 1;
        let solver = LayoutSolver::new(cfg);
        let accesses = vec![
            FieldAccess::read(1, 0, 4, 0x1000),
            FieldAccess::read(1, 16, 4, 0x1004),
        ];
        let s = solver.solve(1, &accesses).unwrap();
        // Pad field with access_count==0 should appear.
        let pads: Vec<_> = s.fields.iter().filter(|f| f.access_count == 0).collect();
        assert!(!pads.is_empty());
        assert!(pads[0].name.starts_with("_pad_"));
        // Real gap still reported.
        let gaps = s.gaps();
        assert_eq!(gaps, vec![(4, 12)]);
    }

    #[test]
    fn type_hint_overrides_size_inferred_type() {
        let solver = LayoutSolver::with_defaults();
        let hinted = FieldAccess::read(1, 0, 4, 0x1000)
            .with_hint(DecompType::Int(rustre_decompiler_expr::IntWidth::U8));
        let s = solver.solve(1, &[hinted]).unwrap();
        let field = s.fields.iter().find(|f| f.access_count > 0).unwrap();
        assert!(matches!(field.field_type, DecompType::Int(rustre_decompiler_expr::IntWidth::U8)));
    }

    #[test]
    fn inferred_type_widths_match_access_size() {
        let solver = LayoutSolver::with_defaults();
        // Bigger gaps so padding/access don't overlap.
        let mut cfg = LayoutSolverConfig::default();
        cfg.min_gap_for_padding = 0;
        let solver2 = LayoutSolver::new(cfg);
        let _ = solver; // keep both around to make sure both compile.
        let sizes = [1u32, 2, 4, 8];
        let mut accesses = Vec::new();
        let mut off = 0i64;
        for &sz in &sizes {
            accesses.push(FieldAccess::read(1, off, sz, 0x1000));
            off += sz as i64;
        }
        let s = solver2.solve(1, &accesses).unwrap();
        let real_fields: Vec<_> = s.fields.iter().filter(|f| f.access_count > 0).collect();
        assert_eq!(real_fields.len(), 4);
        for (f, &sz) in real_fields.iter().zip(sizes.iter()) {
            assert_eq!(f.size_bytes, sz);
            let expected = match sz {
                1 => rustre_decompiler_expr::IntWidth::U8,
                2 => rustre_decompiler_expr::IntWidth::U16,
                4 => rustre_decompiler_expr::IntWidth::U32,
                _ => rustre_decompiler_expr::IntWidth::U64,
            };
            assert!(matches!(&f.field_type, DecompType::Int(w) if *w == expected));
        }
    }

    #[test]
    fn written_flag_tracks_writes() {
        let solver = LayoutSolver::with_defaults();
        let read_only = vec![FieldAccess::read(1, 0, 4, 0x1000)];
        let with_write = vec![
            FieldAccess::read(1, 0, 4, 0x1000),
            FieldAccess::write(1, 0, 4, 0x1004),
        ];
        let s_ro = solver.solve(1, &read_only).unwrap();
        let s_rw = solver.solve(1, &with_write).unwrap();
        assert!(!s_ro.fields.iter().find(|f| f.access_count > 0).unwrap().written);
        assert!(s_rw.fields.iter().find(|f| f.access_count > 0).unwrap().written);
    }

    #[test]
    fn consistency_detects_overlap() {
        // Construct an inconsistent RecoveredStruct manually.
        let s = RecoveredStruct {
            base_var: 1,
            fields: vec![
                RecoveredField {
                    offset: 0, size_bytes: 8,
                    field_type: DecompType::Int(rustre_decompiler_expr::IntWidth::U64),
                    name: "a".into(), access_count: 1, written: false,
                },
                RecoveredField {
                    offset: 4, size_bytes: 4,
                    field_type: DecompType::Int(rustre_decompiler_expr::IntWidth::U32),
                    name: "b".into(), access_count: 1, written: false,
                },
            ],
            total_size: 8,
            confidence: 0.5,
            name: "x".into(),
        };
        assert!(!s.is_consistent());
    }

    #[test]
    fn recovery_results_confident_filter_thresholds() {
        let mut rec = AggregateRecovery::with_defaults();
        rec.record_many(make_accesses());
        let results = rec.solve_all();
        // Threshold of 0 always yields at least one entry.
        assert!(results.confident(0.0).count() > 0);
        // Threshold of 1.01 yields none.
        assert_eq!(results.confident(1.01).count(), 0);
    }

    #[test]
    fn alias_groups_distinct_layouts_no_merge() {
        let mut rec = AggregateRecovery::with_defaults();
        // Two variables with *different* layouts → no alias.
        rec.record(FieldAccess::read(1, 0, 4, 0x1000));
        rec.record(FieldAccess::read(1, 4, 4, 0x1004));
        rec.record(FieldAccess::read(2, 0, 8, 0x2000));
        let results = rec.solve_all();
        let aliases = AliasGroups::from_results(&results);
        assert!(!aliases.may_alias(1, 2));
    }

    #[test]
    fn alias_groups_unknown_var_does_not_alias() {
        let mut rec = AggregateRecovery::with_defaults();
        rec.record(FieldAccess::read(1, 0, 4, 0x1000));
        let results = rec.solve_all();
        let aliases = AliasGroups::from_results(&results);
        // Var 99 is unknown — group_of must be None and may_alias false.
        assert!(aliases.group_of(99).is_none());
        assert!(!aliases.may_alias(99, 1));
    }

    #[test]
    fn access_stats_empty_input_zeros() {
        let stats = AccessStats::compute(7, &[]);
        assert_eq!(stats.total_accesses, 0);
        assert_eq!(stats.unique_offsets, 0);
        assert_eq!(stats.read_count, 0);
        assert_eq!(stats.write_count, 0);
        assert_eq!(stats.min_offset, 0);
        assert_eq!(stats.max_offset, 0);
        assert_eq!(stats.hinted_count, 0);
    }

    #[test]
    fn access_stats_offset_range_and_hint() {
        let accesses = vec![
            FieldAccess::read(1, -4, 4, 0x1).with_hint(DecompType::Int(rustre_decompiler_expr::IntWidth::U32)),
            FieldAccess::write(1, 0, 4, 0x2),
            FieldAccess::read(1, 16, 4, 0x3),
        ];
        let stats = AccessStats::compute(1, &accesses);
        assert_eq!(stats.min_offset, -4);
        assert_eq!(stats.max_offset, 16);
        assert_eq!(stats.unique_offsets, 3);
        assert_eq!(stats.hinted_count, 1);
        assert_eq!(stats.read_count, 2);
        assert_eq!(stats.write_count, 1);
    }

    #[test]
    fn field_access_end_offset_arithmetic() {
        let a = FieldAccess::read(1, 8, 4, 0x100);
        assert_eq!(a.end_offset(), 12);
    }

    #[test]
    fn record_many_groups_per_base_var() {
        let mut rec = AggregateRecovery::with_defaults();
        rec.record_many(vec![
            FieldAccess::read(1, 0, 4, 0x1),
            FieldAccess::read(2, 0, 4, 0x2),
            FieldAccess::read(2, 4, 4, 0x3),
            FieldAccess::read(3, 0, 4, 0x4),
        ]);
        assert_eq!(rec.variable_count(), 3);
        assert_eq!(rec.accesses_for(2).len(), 2);
        assert_eq!(rec.accesses_for(99).len(), 0);
    }

    #[test]
    fn solve_var_unknown_yields_empty_struct() {
        let rec = AggregateRecovery::with_defaults();
        let s = rec.solve_var(123).unwrap();
        assert_eq!(s.base_var, 123);
        assert!(s.fields.is_empty());
    }

    #[test]
    fn results_as_map_keyed_by_base_var() {
        let mut rec = AggregateRecovery::with_defaults();
        rec.record(FieldAccess::read(10, 0, 4, 0x1));
        rec.record(FieldAccess::read(20, 0, 4, 0x2));
        let results = rec.solve_all();
        let map = results.as_map();
        assert!(map.contains_key(&10));
        assert!(map.contains_key(&20));
    }
}
