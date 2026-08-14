//! Struct recovery from field-access patterns.
//!
//! Observes memory accesses relative to a base pointer and groups them into
//! candidate struct types.  Each access `base + offset` with a given `size`
//! corresponds to one field.  Overlapping or conflicting accesses are flagged.
//!
//! # Key types
//! - [`FieldAccess`]          — a single observed memory access through a pointer.
//! - [`RecoveredField`]       — a deduced struct field.
//! - [`RecoveredStruct`]      — a complete recovered struct layout.
//! - [`StructRecoveryEngine`] — the main recovery pass.
//! - [`recover_structs`]      — convenience function.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt::Write as _;

use crate::{RecoveredType, TypeVar};

/// Why a field access could not be recorded.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StructRecoveryError {
    /// The engine already holds as many accesses as it will bound memory for.
    ///
    /// The count comes from the analysed binary, so a crafted file can drive it.
    /// Reporting the cap rather than panicking is what lets a caller abandon one
    /// hostile input instead of losing the process.
    #[error("field-access cap reached ({limit} entries)")]
    TooManyAccesses { limit: usize },
}

// ─────────────────────────────────────────────────────────────────────────────
// FieldAccess
// ─────────────────────────────────────────────────────────────────────────────

/// A single observed field access through a base pointer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldAccess {
    /// The base pointer type variable.
    pub base_var: TypeVar,
    /// Byte offset from the base pointer.
    pub byte_offset: u32,
    /// Size of the access in bytes.
    pub size_bytes: u8,
    /// Whether the access was a write (`true`) or a read (`false`).
    pub is_write: bool,
    /// Program address of the instruction that performed this access.
    pub address: u64,
    /// Heuristic name for the field (e.g. from debug info or type propagation).
    pub hint_name: Option<String>,
}

impl FieldAccess {
    /// Construct a read access.
    #[must_use]
    pub const fn read(base_var: TypeVar, byte_offset: u32, size_bytes: u8, address: u64) -> Self {
        Self {
            base_var,
            byte_offset,
            size_bytes,
            is_write: false,
            address,
            hint_name: None,
        }
    }

    /// Construct a write access.
    #[must_use]
    pub const fn write(base_var: TypeVar, byte_offset: u32, size_bytes: u8, address: u64) -> Self {
        Self {
            base_var,
            byte_offset,
            size_bytes,
            is_write: true,
            address,
            hint_name: None,
        }
    }

    /// Attach a heuristic field name.
    #[must_use]
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.hint_name = Some(name.into());
        self
    }

    /// Byte range `[offset, offset + size)` covered by this access.
    #[must_use]
    pub fn range(&self) -> (u32, u32) {
        (self.byte_offset, self.byte_offset.saturating_add(u32::from(self.size_bytes)))
    }

    /// Return `true` if this access overlaps with `other`.
    #[must_use]
    pub fn overlaps(&self, other: &Self) -> bool {
        let (s1, e1) = self.range();
        let (s2, e2) = other.range();
        s1 < e2 && s2 < e1
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// RecoveredField
// ─────────────────────────────────────────────────────────────────────────────

/// A deduced field in a recovered struct.
#[derive(Debug, Clone)]
pub struct RecoveredField {
    /// Byte offset of the field from the start of the struct.
    pub offset: u32,
    /// Size of the field in bytes.
    pub size: u8,
    /// Type of the field (may be Unknown).
    pub ty: RecoveredType,
    /// Generated or hinted name.
    pub name: String,
    /// Number of accesses through this field observed.
    pub access_count: usize,
    /// Whether any write was observed.
    pub has_write: bool,
}

impl RecoveredField {
    /// Return `true` if this field is likely a pointer (size == `pointer_width`).
    #[must_use]
    pub const fn looks_like_pointer(&self, pointer_width: u8) -> bool {
        self.size == pointer_width && self.ty.is_pointer()
    }

    /// Byte range `[offset, offset + size)`.
    #[must_use]
    pub fn range(&self) -> (u32, u32) {
        (self.offset, self.offset.saturating_add(u32::from(self.size)))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// RecoveredStruct
// ─────────────────────────────────────────────────────────────────────────────

/// A recovered struct layout.
#[derive(Debug, Clone)]
pub struct RecoveredStruct {
    /// The type variable that represents this struct's pointer.
    pub base_var: TypeVar,
    /// Generated name (e.g. `struct_0x7f00`).
    pub name: String,
    /// Recovered fields sorted by offset.
    pub fields: Vec<RecoveredField>,
    /// Total inferred size in bytes (max offset + size of last field).
    pub total_size: u32,
    /// Whether any padding gaps were detected.
    pub has_padding: bool,
    /// Whether any overlapping accesses were observed (union candidate).
    pub has_overlaps: bool,
}

impl RecoveredStruct {
    /// Return the field at a given byte offset, if any.
    #[must_use]
    pub fn field_at(&self, offset: u32) -> Option<&RecoveredField> {
        self.fields.iter().find(|f| f.offset == offset)
    }

    /// Return `true` if the struct has any fields.
    #[must_use]
    pub const fn has_fields(&self) -> bool {
        !self.fields.is_empty()
    }

    /// Produce a C-like text representation.
    #[must_use]
    pub fn to_c_decl(&self) -> String {
        let mut s = format!("struct {} {{\n", self.name);
        for field in &self.fields {
            let type_name = field.ty.display_name();
            let _ = writeln!(
                s,
                "    /* +{:3} */ {} {};",
                field.offset, type_name, field.name
            );
        }
        let _ = writeln!(s, "}}; // size = {}", self.total_size);
        s
    }

    /// Return `true` if this struct could also be a union (all fields at offset 0
    /// with different sizes and overlapping ranges).
    #[must_use]
    pub fn is_union_candidate(&self) -> bool {
        self.has_overlaps && self.fields.iter().all(|f| f.offset == 0)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ConflictKind — describes access conflicts
// ─────────────────────────────────────────────────────────────────────────────

/// Kind of conflict between two field accesses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConflictKind {
    /// Two accesses overlap but are not identical (possible union or alignment
    /// issue).
    Overlap,
    /// Two accesses at the same offset have different sizes.
    SizeMismatch { size_a: u8, size_b: u8 },
}

/// A detected conflict between two field accesses.
#[derive(Debug, Clone)]
pub struct FieldConflict {
    pub offset_a: u32,
    pub offset_b: u32,
    pub kind: ConflictKind,
}

// ─────────────────────────────────────────────────────────────────────────────
// StructRecoveryEngine
// ─────────────────────────────────────────────────────────────────────────────

/// Recovers struct layouts from observed field-access patterns.
///
/// The engine accumulates [`FieldAccess`] observations and, when
/// [`recover_structs`] is called, produces one [`RecoveredStruct`] per
/// distinct base pointer type variable.
#[derive(Debug, Clone)]
pub struct StructRecoveryEngine {
    /// All accumulated field accesses.
    accesses: Vec<FieldAccess>,
    /// Pointer width of the target (4 or 8 bytes).
    pub pointer_width: u8,
    /// Minimum number of distinct accesses required to recover a struct.
    pub min_access_count: usize,
    /// If `true`, attempt to infer field names from hint strings.
    pub use_hints: bool,
}

/// Defaults to the 64-bit configuration.
///
/// BUG FIX: this used to be `#[derive(Default)]`, which produced
/// `pointer_width: 0` and `min_access_count: 0`. Two consequences, both silent:
///
/// * `min_access_count == 0` made `recover_for` return `Some` for **every**
///   type variable, observed or not — a zero-field struct presented as a
///   finding. "This is a struct with no fields" is a claim; the absence of
///   evidence should produce no claim at all.
/// * `pointer_width == 0` made `looks_like_pointer` unable to ever fire, so the
///   pointer rung of the recovery ladder was dead in any engine built this way.
///
/// `Default::default()` is the obvious way to construct this type, so the
/// derive was a trap rather than a convenience.
impl Default for StructRecoveryEngine {
    fn default() -> Self {
        Self::new_64bit()
    }
}

impl StructRecoveryEngine {
    /// Create a new engine for 64-bit targets.
    #[must_use]
    pub const fn new_64bit() -> Self {
        Self {
            pointer_width: 8,
            min_access_count: 1,
            use_hints: true,
            accesses: vec![],
        }
    }

    /// Create a new engine for 32-bit targets.
    #[must_use]
    pub const fn new_32bit() -> Self {
        Self {
            pointer_width: 4,
            min_access_count: 1,
            use_hints: true,
            accesses: vec![],
        }
    }

    /// Hard cap on recorded field accesses, bounding memory use on a hostile
    /// binary.
    pub const MAX_ACCESSES: usize = 8 * 1024 * 1024;

    /// Record a field access, or report that the cap is reached.
    ///
    /// Prefer this over [`Self::record`] on any path fed by a binary: the
    /// accesses come from the analysed file, so their number is
    /// attacker-influenced. `record` panics at the cap — which turns the
    /// denial-of-service its own doc comment warns about into a process kill —
    /// while this returns an error the caller can handle.
    ///
    /// # Errors
    /// Returns [`StructRecoveryError::TooManyAccesses`] when the cap is reached.
    pub fn try_record(&mut self, access: FieldAccess) -> Result<(), StructRecoveryError> {
        if self.accesses.len() >= Self::MAX_ACCESSES {
            return Err(StructRecoveryError::TooManyAccesses {
                limit: Self::MAX_ACCESSES,
            });
        }
        self.accesses.push(access);
        Ok(())
    }

    /// Record many field accesses, stopping at the cap.
    ///
    /// Returns how many were recorded, so a caller can tell a complete run from
    /// a truncated one. `record_all` panicked *after* having already pushed part
    /// of its input, leaving the engine half-filled with no way to know it.
    ///
    /// # Errors
    /// Returns [`StructRecoveryError::TooManyAccesses`] if the cap is reached
    /// before the input is exhausted.
    pub fn try_record_all(
        &mut self,
        accesses: impl IntoIterator<Item = FieldAccess>,
    ) -> Result<usize, StructRecoveryError> {
        let mut n = 0usize;
        for acc in accesses {
            self.try_record(acc)?;
            n += 1;
        }
        Ok(n)
    }

    /// Record a field access.
    ///
    /// # Panics
    /// Panics if the number of recorded accesses would exceed
    /// [`Self::MAX_ACCESSES`]. Use [`Self::try_record`] when the accesses come
    /// from an untrusted binary.
    pub fn record(&mut self, access: FieldAccess) {
        self.try_record(access)
            .expect("StructRecoveryEngine: field-access cap reached; use try_record");
    }

    /// Record multiple field accesses.
    ///
    /// # Panics
    /// Panics if the total number of recorded accesses would exceed
    /// `MAX_ACCESSES` (8 M), preventing denial-of-service via memory
    /// exhaustion when analysing adversarially-crafted binaries.
    pub fn record_all(&mut self, accesses: impl IntoIterator<Item = FieldAccess>) {
        self.try_record_all(accesses)
            .expect("StructRecoveryEngine: field-access cap reached; use try_record_all");
    }

    /// Return the number of recorded accesses.
    #[must_use]
    pub const fn access_count(&self) -> usize {
        self.accesses.len()
    }

    /// Run struct recovery and return one [`RecoveredStruct`] per unique base var.
    #[must_use]
    pub fn recover_structs_all(&self) -> Vec<RecoveredStruct> {
        recover_structs(
            &self.accesses,
            self.pointer_width,
            self.min_access_count,
            self.use_hints,
        )
    }

    /// Recover a struct for a specific base variable.
    #[must_use]
    pub fn recover_for(&self, base_var: TypeVar) -> Option<RecoveredStruct> {
        let accesses: Vec<&FieldAccess> =
            self.accesses.iter().filter(|a| a.base_var == base_var).collect();
        if accesses.len() < self.min_access_count {
            return None;
        }
        Some(build_struct(base_var, &accesses, self.pointer_width, self.use_hints))
    }

    /// Check for conflicts in the recorded accesses for `base_var`.
    #[must_use]
    pub fn find_conflicts(&self, base_var: TypeVar) -> Vec<FieldConflict> {
        let accesses: Vec<&FieldAccess> =
            self.accesses.iter().filter(|a| a.base_var == base_var).collect();
        detect_conflicts(&accesses)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// recover_structs  — public entry point
// ─────────────────────────────────────────────────────────────────────────────

/// Recover struct layouts from a set of field accesses.
///
/// Returns one [`RecoveredStruct`] per distinct `base_var` that meets the
/// `min_access_count` threshold.
#[must_use]
pub fn recover_structs(
    accesses: &[FieldAccess],
    pointer_width: u8,
    min_access_count: usize,
    use_hints: bool,
) -> Vec<RecoveredStruct> {
    // Group accesses by base_var.
    // Use BTreeMap so that attacker-controlled TypeVar keys (from binary
    // addresses/offsets) cannot trigger hash-collision denial-of-service.
    let mut by_base: BTreeMap<TypeVar, Vec<&FieldAccess>> = BTreeMap::new();
    for acc in accesses {
        by_base.entry(acc.base_var).or_default().push(acc);
    }

    let mut result: Vec<RecoveredStruct> = by_base
        .into_iter()
        .filter(|(_, group)| group.len() >= min_access_count)
        .map(|(base_var, group)| build_struct(base_var, &group, pointer_width, use_hints))
        .collect();

    // Sort by base_var for determinism.
    result.sort_by_key(|s| s.base_var.0);
    result
}

fn build_struct(
    base_var: TypeVar,
    accesses: &[&FieldAccess],
    pointer_width: u8,
    use_hints: bool,
) -> RecoveredStruct {
    // Merge accesses at the same offset with the same size.
    // Key = (offset, size_bytes).
    let mut field_map: HashMap<(u32, u8), (usize, bool, Option<String>)> = HashMap::new();
    for acc in accesses {
        let key = (acc.byte_offset, acc.size_bytes);
        // The initial insert must respect `use_hints` too — otherwise the
        // first access's hint leaks into the field name even when hints are
        // disabled.
        let entry = field_map
            .entry(key)
            .or_insert_with(|| (0, false, if use_hints { acc.hint_name.clone() } else { None }));
        entry.0 += 1; // access_count
        if acc.is_write {
            entry.1 = true; // has_write
        }
        if use_hints && entry.2.is_none() {
            entry.2.clone_from(&acc.hint_name);
        }
    }

    // Build field list.
    let mut fields: Vec<RecoveredField> = field_map
        .into_iter()
        .map(|((offset, size), (count, has_write, hint))| {
            let ty = infer_field_type(size, pointer_width);
            let name = hint.unwrap_or_else(|| format!("field_{offset:x}"));
            RecoveredField {
                offset,
                size,
                ty,
                name,
                access_count: count,
                has_write,
            }
        })
        .collect();

    // Sort fields by offset.
    fields.sort_by(|a, b| a.offset.cmp(&b.offset).then(b.size.cmp(&a.size)));

    // Compute total size.
    let total_size = fields
        .iter()
        .map(|f| f.offset.saturating_add(u32::from(f.size)))
        .max()
        .unwrap_or(0);

    // Detect padding gaps.
    let has_padding = detect_padding(&fields);

    // Detect overlaps. Any conflict — whether classified as a byte-range
    // `Overlap` or a same-offset `SizeMismatch` — means the accesses share
    // memory, which is exactly the union-candidate signal; a `SizeMismatch`
    // at the same offset is itself an overlap (they share at least one
    // byte), so it must count too.
    let conflicts = detect_conflicts(accesses);
    let has_overlaps = !conflicts.is_empty();

    let name = format!("struct_{:08x}", base_var.0);

    RecoveredStruct {
        base_var,
        name,
        fields,
        total_size,
        has_padding,
        has_overlaps,
    }
}

fn infer_field_type(size_bytes: u8, pointer_width: u8) -> RecoveredType {
    // pointer_width == 0 is an invalid sentinel (default-constructed engine);
    // treat zero as "unknown pointer width" and never match it.
    if pointer_width > 0 && size_bytes == pointer_width {
        // Ambiguous: could be integer or pointer.  Default to pointer for
        // pointer-width accesses (common in struct layouts).
        RecoveredType::Pointer(Box::new(RecoveredType::Unknown))
    } else {
        RecoveredType::Int {
            width: size_bytes,
            signed: false,
        }
    }
}

fn detect_padding(fields: &[RecoveredField]) -> bool {
    let mut cursor: u32 = 0;
    for f in fields {
        if f.offset > cursor {
            return true; // gap before this field
        }
        cursor = cursor.max(f.offset.saturating_add(u32::from(f.size)));
    }
    false
}

fn detect_conflicts(accesses: &[&FieldAccess]) -> Vec<FieldConflict> {
    let mut conflicts = Vec::new();
    let n = accesses.len();
    for i in 0..n {
        for j in (i + 1)..n {
            let a = accesses[i];
            let b = accesses[j];
            if !a.overlaps(b) {
                continue;
            }
            if a.byte_offset == b.byte_offset && a.size_bytes != b.size_bytes {
                conflicts.push(FieldConflict {
                    offset_a: a.byte_offset,
                    offset_b: b.byte_offset,
                    kind: ConflictKind::SizeMismatch {
                        size_a: a.size_bytes,
                        size_b: b.size_bytes,
                    },
                });
            } else if a.byte_offset != b.byte_offset {
                conflicts.push(FieldConflict {
                    offset_a: a.byte_offset,
                    offset_b: b.byte_offset,
                    kind: ConflictKind::Overlap,
                });
            }
        }
    }
    conflicts
}

// ─────────────────────────────────────────────────────────────────────────────
// StructMerger — merge two recovered structs
// ─────────────────────────────────────────────────────────────────────────────

/// Merge two [`RecoveredStruct`]s that are believed to describe the same type.
///
/// Fields at the same offset/size are de-duplicated.  Fields at different
/// offsets/sizes are union'd.
#[must_use]
pub fn merge_structs(a: &RecoveredStruct, b: &RecoveredStruct) -> RecoveredStruct {
    let mut field_map: HashMap<(u32, u8), RecoveredField> = HashMap::new();
    for f in a.fields.iter().chain(b.fields.iter()) {
        let key = (f.offset, f.size);
        match field_map.entry(key) {
            std::collections::hash_map::Entry::Vacant(e) => {
                e.insert(f.clone());
            }
            std::collections::hash_map::Entry::Occupied(mut e) => {
                let entry = e.get_mut();
                entry.access_count += f.access_count;
                if f.has_write {
                    entry.has_write = true;
                }
                // Information-preserving merges (previously the right-hand
                // struct's type and name were silently dropped, making the
                // merged struct depend on operand order):
                // - a concrete field type must never be replaced by (or lose
                //   to) Unknown;
                if matches!(entry.ty, RecoveredType::Unknown)
                    && !matches!(f.ty, RecoveredType::Unknown)
                {
                    entry.ty = f.ty.clone();
                }
                // - a hinted name must never lose to an auto-generated
                //   `field_<off>` placeholder. Two distinct hints keep the
                //   left operand's (documented tie-break).
                let generated = format!("field_{:x}", f.offset);
                if entry.name == generated && f.name != generated {
                    entry.name.clone_from(&f.name);
                }
            }
        }
    }
    let mut fields: Vec<RecoveredField> = field_map.into_values().collect();
    fields.sort_by(|a, b| a.offset.cmp(&b.offset).then(b.size.cmp(&a.size)));
    let total_size = fields
        .iter()
        .map(|f| f.offset.saturating_add(u32::from(f.size)))
        .max()
        .unwrap_or(0);
    let has_padding = detect_padding(&fields);
    // Merging can introduce overlaps that neither input struct had on its
    // own (e.g. a field from `a` at [0,8) and a field from `b` at [4,8)
    // never conflicted while the structs were separate). Recompute over
    // the merged field set rather than just OR-ing the inputs' flags,
    // otherwise a genuine union candidate silently reads as clean.
    let has_overlaps = a.has_overlaps || b.has_overlaps || fields_overlap(&fields);
    RecoveredStruct {
        base_var: a.base_var,
        name: a.name.clone(),
        fields,
        total_size,
        has_padding,
        has_overlaps,
    }
}

/// Return `true` if any two fields in `fields` have overlapping byte ranges.
fn fields_overlap(fields: &[RecoveredField]) -> bool {
    for i in 0..fields.len() {
        for j in (i + 1)..fields.len() {
            let (s1, e1) = fields[i].range();
            let (s2, e2) = fields[j].range();
            if s1 < e2 && s2 < e1 {
                return true;
            }
        }
    }
    false
}

// ─────────────────────────────────────────────────────────────────────────────
// StructDatabase — stores and looks up recovered structs
// ─────────────────────────────────────────────────────────────────────────────

/// A collection of recovered structs indexed by base type variable.
///
/// Uses [`BTreeMap`] rather than [`HashMap`] so that attacker-controlled
/// [`TypeVar`] keys (derived from binary addresses / offsets) cannot trigger
/// hash-collision denial-of-service that degrades lookups from O(1) to O(n).
#[derive(Debug, Clone, Default)]
pub struct StructDatabase {
    structs: BTreeMap<TypeVar, RecoveredStruct>,
}

impl StructDatabase {
    /// Create an empty database.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert or merge a recovered struct.
    pub fn insert(&mut self, s: RecoveredStruct) {
        let key = s.base_var;
        match self.structs.get(&key) {
            None => {
                self.structs.insert(key, s);
            }
            Some(existing) => {
                let merged = merge_structs(existing, &s);
                self.structs.insert(key, merged);
            }
        }
    }

    /// Look up a struct by base type variable.
    #[must_use]
    pub fn get(&self, base_var: TypeVar) -> Option<&RecoveredStruct> {
        self.structs.get(&base_var)
    }

    /// Return all recovered structs in insertion order (non-deterministic).
    #[must_use]
    pub fn all_structs(&self) -> Vec<&RecoveredStruct> {
        let mut v: Vec<&RecoveredStruct> = self.structs.values().collect();
        v.sort_by_key(|s| s.base_var.0);
        v
    }

    /// Number of structs in the database.
    #[must_use]
    pub fn len(&self) -> usize {
        self.structs.len()
    }

    /// Return `true` if the database is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.structs.is_empty()
    }

    /// Collect all struct names as a set (for name uniqueness checks).
    #[must_use]
    pub fn names(&self) -> HashSet<&str> {
        self.structs.values().map(|s| s.name.as_str()).collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn tv(n: u32) -> TypeVar {
        TypeVar::new(n)
    }

    /// With `use_hints == false` the field name must be the generated
    /// `field_<off>` even when the FIRST access at that (offset, size)
    /// carries a hint. The old code only honoured `use_hints` for later
    /// accesses: `or_insert_with` copied the first access's hint
    /// unconditionally, so this test fails against it with name "hinted".
    #[test]
    fn use_hints_false_ignores_hint_on_first_access() {
        let accesses = vec![
            FieldAccess::read(tv(1), 8, 4, 0x1000).with_name("hinted"),
            FieldAccess::read(tv(1), 8, 4, 0x1004),
        ];
        let structs = recover_structs(&accesses, 8, 1, false);
        assert_eq!(structs.len(), 1);
        assert_eq!(structs[0].fields.len(), 1);
        assert_eq!(
            structs[0].fields[0].name, "field_8",
            "use_hints=false must not leak the first access's hint"
        );
        // Sanity: with use_hints=true the hint IS used.
        let structs = recover_structs(&accesses, 8, 1, true);
        assert_eq!(structs[0].fields[0].name, "hinted");
    }

    /// `merge_structs` must be order-independent in its *field content*: field
    /// set (offset/size/summed access_count/OR'd has_write), `total_size`, and
    /// especially `has_overlaps` (the iter-43 fix recomputes overlaps over the
    /// merged layout) must not depend on the order structs are folded. Only
    /// `name`/`base_var` are taken from the left operand by design.
    #[test]
    fn merge_structs_field_content_is_order_independent() {
        use crate::test_prng::xorshift as xs;
        fn mk(seed: &mut u64) -> RecoveredStruct {
            let nf = 1 + (xs(seed) % 4) as usize;
            let mut fields = Vec::new();
            for _ in 0..nf {
                let offset = (xs(seed) % 5) as u32 * 4; // 0,4,8,12,16
                let size = [1u8, 2, 4, 8][(xs(seed) % 4) as usize];
                fields.push(RecoveredField {
                    offset,
                    size,
                    ty: RecoveredType::Unknown,
                    name: format!("f{offset}"),
                    access_count: 1 + (xs(seed) % 3) as usize,
                    has_write: xs(seed) % 2 == 0,
                });
            }
            RecoveredStruct {
                base_var: tv(0),
                name: "s".into(),
                fields,
                total_size: 0,
                has_padding: false,
                has_overlaps: false,
            }
        }
        // Canonical fingerprint of a struct's field content (order-insensitive).
        fn fp(s: &RecoveredStruct) -> (Vec<(u32, u8, usize, bool)>, u32, bool) {
            let mut v: Vec<(u32, u8, usize, bool)> = s
                .fields
                .iter()
                .map(|f| (f.offset, f.size, f.access_count, f.has_write))
                .collect();
            v.sort_unstable();
            (v, s.total_size, s.has_overlaps)
        }
        let mut state = 0xabcd_1234_5678_9f01u64;
        for _ in 0..500 {
            let a = mk(&mut state);
            let b = mk(&mut state);
            let c = mk(&mut state);
            // Different fold orders over the same 3 structs.
            let left = merge_structs(&merge_structs(&a, &b), &c);
            let right = merge_structs(&a, &merge_structs(&b, &c));
            let swapped = merge_structs(&merge_structs(&c, &b), &a);
            assert_eq!(fp(&left), fp(&right), "merge not associative: a={a:?} b={b:?} c={c:?}");
            assert_eq!(fp(&left), fp(&swapped), "merge not commutative in field content");
        }
    }

    /// Regression: merge_structs dropped the right operand's field type and
    /// hinted name when the (offset,size) key already existed — so
    /// merge(a,b) kept a concrete type/hint while merge(b,a) lost it to
    /// Unknown/`field_<off>` depending only on operand order.
    #[test]
    fn regression_merge_structs_keeps_concrete_ty_and_hint_regardless_of_order() {
        let mk = |ty: RecoveredType, name: &str| RecoveredStruct {
            base_var: tv(0),
            name: "s".into(),
            fields: vec![RecoveredField {
                offset: 8,
                size: 4,
                ty,
                name: name.into(),
                access_count: 1,
                has_write: false,
            }],
            total_size: 12,
            has_padding: true,
            has_overlaps: false,
        };
        let unk = mk(RecoveredType::Unknown, "field_8");
        let hinted = mk(RecoveredType::Int { width: 4, signed: true }, "count");
        for (l, r) in [(&unk, &hinted), (&hinted, &unk)] {
            let m = merge_structs(l, r);
            assert_eq!(m.fields.len(), 1);
            assert_eq!(
                m.fields[0].ty,
                RecoveredType::Int { width: 4, signed: true },
                "concrete field type lost when merging {l:?} + {r:?}"
            );
            assert_eq!(m.fields[0].name, "count", "hinted name lost to generated placeholder");
        }
    }

    /// Property: merging never loses a field — the merged (offset,size) key
    /// set is exactly the union of the inputs', even when ranges overlap.
    #[test]
    fn prop_merge_structs_no_field_lost_on_overlap() {
        use crate::test_prng::xorshift as xs;
        let mut s = 0x5eed_5eed_5eed_5eedu64;
        for iter in 0..500 {
            let mut mk = |s: &mut u64| {
                let n = 1 + (xs(s) % 5) as usize;
                let accesses: Vec<FieldAccess> = (0..n)
                    .map(|_| {
                        // Deliberately dense offsets so overlaps are common.
                        FieldAccess::read(
                            tv(0),
                            (xs(s) % 12) as u32,
                            [1u8, 2, 4, 8][(xs(s) % 4) as usize],
                            0,
                        )
                    })
                    .collect();
                recover_structs(&accesses, 8, 1, false).into_iter().next().unwrap()
            };
            let a = mk(&mut s);
            let b = mk(&mut s);
            let keys = |st: &RecoveredStruct| {
                let mut v: Vec<(u32, u8)> = st.fields.iter().map(|f| (f.offset, f.size)).collect();
                v.sort_unstable();
                v.dedup();
                v
            };
            let m = merge_structs(&a, &b);
            let mut expected = keys(&a);
            expected.extend(keys(&b));
            expected.sort_unstable();
            expected.dedup();
            assert_eq!(
                keys(&m),
                expected,
                "iter {iter}: field lost in merge of {a:?} + {b:?}"
            );
        }
    }

    /// Property: merging a struct with itself changes nothing about its
    /// layout — field set, offsets, sizes, types, names, total_size and
    /// flags are all unchanged. (access_count is summed by design: it is an
    /// observation aggregate, not part of the layout lattice.)
    #[test]
    fn prop_merge_structs_idempotent_layout() {
        use crate::test_prng::xorshift as xs;
        let mut s = 0x0dd_ba11_c0ffeeu64;
        for iter in 0..500 {
            let n = 1 + (xs(&mut s) % 5) as usize;
            let accesses: Vec<FieldAccess> = (0..n)
                .map(|_| {
                    FieldAccess::read(
                        tv(0),
                        (xs(&mut s) % 16) as u32,
                        [1u8, 2, 4, 8][(xs(&mut s) % 4) as usize],
                        0,
                    )
                })
                .collect();
            let a = recover_structs(&accesses, 8, 1, false).into_iter().next().unwrap();
            let m = merge_structs(&a, &a);
            let layout = |st: &RecoveredStruct| {
                let mut v: Vec<(u32, u8, String, String)> = st
                    .fields
                    .iter()
                    .map(|f| (f.offset, f.size, f.ty.display_name(), f.name.clone()))
                    .collect();
                v.sort_unstable();
                (v, st.total_size, st.has_padding, st.has_overlaps)
            };
            assert_eq!(layout(&m), layout(&a), "iter {iter}: self-merge changed layout of {a:?}");
        }
    }

    /// Property: folding structs in any order yields the same field
    /// types/names too (the earlier order-independence test only covered
    /// offset/size/count/write). One hint per (offset,size) key at most, so
    /// no documented left-bias tie-break is exercised.
    #[test]
    fn prop_merge_structs_ty_and_name_order_independent() {
        let mk = |offset: u32, size: u8, ty: RecoveredType, name: &str| RecoveredStruct {
            base_var: tv(0),
            name: "s".into(),
            fields: vec![RecoveredField {
                offset,
                size,
                ty,
                name: name.into(),
                access_count: 1,
                has_write: false,
            }],
            total_size: offset + u32::from(size),
            has_padding: false,
            has_overlaps: false,
        };
        let a = mk(0, 4, RecoveredType::Unknown, "field_0");
        let b = mk(0, 4, RecoveredType::Int { width: 4, signed: false }, "id");
        let c = mk(4, 8, RecoveredType::Pointer(Box::new(RecoveredType::Unknown)), "field_4");
        let fp = |st: &RecoveredStruct| {
            let mut v: Vec<(u32, u8, String, String)> = st
                .fields
                .iter()
                .map(|f| (f.offset, f.size, f.ty.display_name(), f.name.clone()))
                .collect();
            v.sort_unstable();
            v
        };
        let orders = [
            merge_structs(&merge_structs(&a, &b), &c),
            merge_structs(&merge_structs(&c, &b), &a),
            merge_structs(&a, &merge_structs(&b, &c)),
            merge_structs(&merge_structs(&b, &a), &c),
        ];
        for (i, m) in orders.iter().enumerate().skip(1) {
            assert_eq!(fp(&orders[0]), fp(m), "fold order {i} produced different ty/name content");
        }
    }

    #[test]
    fn test_simple_struct_recovery() {
        let accesses = vec![
            FieldAccess::read(tv(0), 0, 8, 0x1000),  // ptr field at 0
            FieldAccess::read(tv(0), 8, 4, 0x1004),  // i32 at 8
            FieldAccess::write(tv(0), 12, 4, 0x1008), // i32 at 12
        ];
        let structs = recover_structs(&accesses, 8, 1, false);
        assert_eq!(structs.len(), 1);
        let s = &structs[0];
        assert_eq!(s.fields.len(), 3);
        assert_eq!(s.total_size, 16);
    }

    #[test]
    fn test_two_distinct_base_vars() {
        let accesses = vec![
            FieldAccess::read(tv(0), 0, 4, 0x1000),
            FieldAccess::read(tv(1), 0, 8, 0x2000),
        ];
        let structs = recover_structs(&accesses, 8, 1, false);
        assert_eq!(structs.len(), 2);
    }

    #[test]
    fn test_min_access_count_filter() {
        let accesses = vec![FieldAccess::read(tv(0), 0, 4, 0)];
        // Require at least 2 accesses.
        let structs = recover_structs(&accesses, 8, 2, false);
        assert!(structs.is_empty());
    }

    #[test]
    fn test_field_overlap_detection() {
        // Overlapping accesses at same base.
        let accesses = vec![
            FieldAccess::read(tv(0), 0, 8, 0), // covers [0,8)
            FieldAccess::read(tv(0), 4, 4, 4), // covers [4,8) — overlaps
        ];
        let engine = {
            let mut e = StructRecoveryEngine::new_64bit();
            e.record_all(accesses.clone());
            e
        };
        let conflicts = engine.find_conflicts(tv(0));
        assert!(!conflicts.is_empty());
    }

    #[test]
    fn test_padding_detection() {
        // Gap between offset 4 and offset 8 → padding.
        let accesses = vec![
            FieldAccess::read(tv(0), 0, 4, 0), // [0,4)
            FieldAccess::read(tv(0), 8, 4, 4), // [8,12) — gap at [4,8)
        ];
        let structs = recover_structs(&accesses, 8, 1, false);
        assert!(structs[0].has_padding);
    }

    #[test]
    fn test_c_decl_output() {
        let accesses = vec![
            FieldAccess::read(tv(0), 0, 8, 0).with_name("next"),
            FieldAccess::read(tv(0), 8, 4, 4).with_name("value"),
        ];
        let structs = recover_structs(&accesses, 8, 1, true);
        let decl = structs[0].to_c_decl();
        assert!(decl.contains("next"));
        assert!(decl.contains("value"));
    }

    #[test]
    fn test_struct_database_merge() {
        let mut db = StructDatabase::new();
        let accesses1 = vec![FieldAccess::read(tv(0), 0, 8, 0)];
        let accesses2 = vec![FieldAccess::read(tv(0), 8, 4, 4)];
        let s1 = recover_structs(&accesses1, 8, 1, false).into_iter().next().unwrap();
        let s2 = recover_structs(&accesses2, 8, 1, false).into_iter().next().unwrap();
        db.insert(s1);
        db.insert(s2);
        assert_eq!(db.len(), 1);
        let merged = db.get(tv(0)).unwrap();
        assert_eq!(merged.fields.len(), 2);
    }

    #[test]
    fn test_merge_structs() {
        let accesses_a = vec![FieldAccess::read(tv(0), 0, 4, 0)];
        let accesses_b = vec![FieldAccess::write(tv(0), 4, 4, 4)];
        let sa = &recover_structs(&accesses_a, 4, 1, false)[0];
        let sb = &recover_structs(&accesses_b, 4, 1, false)[0];
        let merged = merge_structs(sa, sb);
        assert_eq!(merged.fields.len(), 2);
        assert_eq!(merged.total_size, 8);
    }

    #[test]
    fn test_field_at_lookup() {
        let accesses = vec![
            FieldAccess::read(tv(0), 0, 4, 0),
            FieldAccess::read(tv(0), 8, 8, 4),
        ];
        let s = &recover_structs(&accesses, 8, 1, false)[0];
        assert!(s.field_at(0).is_some());
        assert!(s.field_at(8).is_some());
        assert!(s.field_at(4).is_none());
    }

    #[test]
    fn test_recover_for_method() {
        let mut engine = StructRecoveryEngine::new_64bit();
        engine.record(FieldAccess::read(tv(0), 0, 8, 0));
        engine.record(FieldAccess::read(tv(0), 8, 4, 4));
        let s = engine.recover_for(tv(0)).unwrap();
        assert_eq!(s.fields.len(), 2);
    }

    // ── Additional coverage: merge_structs cross-overlap bug ────────────────

    #[test]
    fn test_merge_structs_detects_new_overlap() {
        // `a` has a single field [0,8) — no internal overlap.
        // `b` has a single field [4,8) — no internal overlap either.
        // Merged, the two fields overlap in [4,8), which neither struct's
        // own `has_overlaps` flag could have recorded on its own.
        let accesses_a = vec![FieldAccess::read(tv(0), 0, 8, 0)];
        let accesses_b = vec![FieldAccess::read(tv(0), 4, 4, 4)];
        let sa = &recover_structs(&accesses_a, 8, 1, false)[0];
        let sb = &recover_structs(&accesses_b, 8, 1, false)[0];
        assert!(!sa.has_overlaps);
        assert!(!sb.has_overlaps);
        let merged = merge_structs(sa, sb);
        assert_eq!(merged.fields.len(), 2);
        assert!(
            merged.has_overlaps,
            "merging fields at [0,8) and [4,8) must be flagged as overlapping"
        );
    }

    #[test]
    fn test_merge_structs_no_false_positive_overlap() {
        // Non-overlapping fields from each struct: merge must not spuriously
        // flag an overlap.
        let accesses_a = vec![FieldAccess::read(tv(0), 0, 4, 0)];
        let accesses_b = vec![FieldAccess::read(tv(0), 4, 4, 4)];
        let sa = &recover_structs(&accesses_a, 8, 1, false)[0];
        let sb = &recover_structs(&accesses_b, 8, 1, false)[0];
        let merged = merge_structs(sa, sb);
        assert!(!merged.has_overlaps);
    }

    #[test]
    fn test_struct_database_insert_propagates_new_overlap() {
        // Same scenario as above but exercised through StructDatabase::insert,
        // which is the real caller of merge_structs in the pipeline.
        let mut db = StructDatabase::new();
        let accesses1 = vec![FieldAccess::read(tv(0), 0, 8, 0)];
        let accesses2 = vec![FieldAccess::read(tv(0), 4, 4, 4)];
        let s1 = recover_structs(&accesses1, 8, 1, false).into_iter().next().unwrap();
        let s2 = recover_structs(&accesses2, 8, 1, false).into_iter().next().unwrap();
        db.insert(s1);
        db.insert(s2);
        let merged = db.get(tv(0)).unwrap();
        assert!(merged.has_overlaps);
    }

    // ── Additional coverage: misc public API ────────────────────────────────

    #[test]
    fn test_field_access_range_and_overlaps() {
        let a = FieldAccess::read(tv(0), 4, 4, 0); // [4,8)
        let b = FieldAccess::read(tv(0), 6, 4, 0); // [6,10)
        let c = FieldAccess::read(tv(0), 8, 4, 0); // [8,12)
        assert_eq!(a.range(), (4, 8));
        assert!(a.overlaps(&b));
        assert!(!a.overlaps(&c)); // touching but not overlapping
    }

    #[test]
    fn test_looks_like_pointer() {
        let accesses = vec![FieldAccess::read(tv(0), 0, 8, 0)];
        let s = &recover_structs(&accesses, 8, 1, false)[0];
        assert!(s.fields[0].looks_like_pointer(8));
        assert!(!s.fields[0].looks_like_pointer(4));
    }

    #[test]
    fn test_is_union_candidate() {
        // Two accesses at offset 0 with different sizes → union candidate.
        let accesses = vec![
            FieldAccess::read(tv(0), 0, 8, 0),
            FieldAccess::read(tv(0), 0, 4, 4),
        ];
        let s = &recover_structs(&accesses, 8, 1, false)[0];
        assert!(s.is_union_candidate());
    }

    #[test]
    fn test_find_conflicts_size_mismatch() {
        let mut engine = StructRecoveryEngine::new_64bit();
        engine.record(FieldAccess::read(tv(0), 0, 8, 0));
        engine.record(FieldAccess::read(tv(0), 0, 4, 4));
        let conflicts = engine.find_conflicts(tv(0));
        assert!(conflicts
            .iter()
            .any(|c| matches!(c.kind, ConflictKind::SizeMismatch { .. })));
    }

    #[test]
    fn test_recover_for_below_min_access_count() {
        let mut engine = StructRecoveryEngine::new_64bit();
        engine.min_access_count = 3;
        engine.record(FieldAccess::read(tv(0), 0, 8, 0));
        assert!(engine.recover_for(tv(0)).is_none());
    }

    #[test]
    fn test_struct_database_names_and_is_empty() {
        let mut db = StructDatabase::new();
        assert!(db.is_empty());
        let accesses = vec![FieldAccess::read(tv(0), 0, 8, 0)];
        let s = recover_structs(&accesses, 8, 1, false).into_iter().next().unwrap();
        db.insert(s);
        assert!(!db.is_empty());
        assert!(db.names().contains(format!("struct_{:08x}", 0).as_str()));
    }
}
