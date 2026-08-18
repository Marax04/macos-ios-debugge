//! Union detection from overlapping memory-access evidence.
//!
//! The [`crate::aggregate_recovery::LayoutSolver`] resolves overlapping field
//! accesses by either dropping the narrower access or erroring out.  Real
//! binaries, however, contain genuine C `union`s: the *same* offset (relative
//! to a base pointer) is accessed with *different widths* or *different
//! scalar classes* (int vs float) on different code paths.
//!
//! [`UnionDetector`] consumes the same [`FieldAccess`] evidence stream and
//! reports offsets whose access pattern is union-like, materialising a
//! [`UnionType`] per site.  It is designed to run *before* the layout solver
//! so that detected union regions can be collapsed into a single field.

use std::collections::BTreeMap;

use crate::aggregate_recovery::FieldAccess;
use crate::{DecompType, StructField, UnionType};
use rustre_decompiler_expr::IntWidth;

/// One offset within a base variable that shows union-like access behaviour.
#[derive(Debug, Clone, PartialEq)]
pub struct UnionCandidate {
    /// Base variable the accesses were observed on.
    pub base_var: u32,
    /// Byte offset (relative to the base pointer) where the union starts.
    pub offset: i64,
    /// Distinct access widths observed at this offset, ascending.
    pub widths: Vec<u32>,
    /// Total size of the union region (max width observed).
    pub total_size: u32,
    /// True when both float-typed and int-typed hints were seen (strong signal).
    pub mixed_scalar_class: bool,
    /// Number of accesses supporting this candidate.
    pub evidence_count: usize,
    /// Confidence in [0, 1].
    pub confidence: f64,
}

impl UnionCandidate {
    /// Materialise a named [`UnionType`] with one member per observed width.
    #[must_use]
    pub fn to_union_type(&self) -> UnionType {
        let members: Vec<StructField> = self
            .widths
            .iter()
            .map(|&w| {
                let ty = int_type_for_width(w);
                StructField::new(0, format!("as_{}", width_suffix(w)), ty)
            })
            .collect();
        UnionType::new(
            format!("union_{}_{:x}", self.base_var, self.offset.unsigned_abs()),
            members,
        )
    }
}

fn int_type_for_width(w: u32) -> DecompType {
    match w {
        1 => DecompType::Int(IntWidth::U8),
        2 => DecompType::Int(IntWidth::U16),
        4 => DecompType::Int(IntWidth::U32),
        8 => DecompType::Int(IntWidth::U64),
        n => DecompType::Array(Box::new(DecompType::Int(IntWidth::U8)), u64::from(n)),
    }
}

fn width_suffix(w: u32) -> String {
    match w {
        1 => "u8".to_string(),
        2 => "u16".to_string(),
        4 => "u32".to_string(),
        8 => "u64".to_string(),
        n => format!("bytes{n}"),
    }
}

/// Configuration for union detection.
#[derive(Debug, Clone)]
pub struct UnionDetectorConfig {
    /// Minimum number of distinct widths at the same offset to report a union.
    pub min_distinct_widths: usize,
    /// Minimum total supporting accesses.
    pub min_evidence: usize,
}

impl Default for UnionDetectorConfig {
    fn default() -> Self {
        Self {
            min_distinct_widths: 2,
            min_evidence: 2,
        }
    }
}

/// Detects union-like access patterns in a [`FieldAccess`] stream.
#[derive(Debug, Default)]
pub struct UnionDetector {
    config: UnionDetectorConfig,
    accesses: Vec<FieldAccess>,
}

impl UnionDetector {
    #[must_use]
    pub const fn new(config: UnionDetectorConfig) -> Self {
        Self {
            config,
            accesses: Vec::new(),
        }
    }

    #[must_use]
    pub fn with_defaults() -> Self {
        Self::new(UnionDetectorConfig::default())
    }

    /// Record one access.
    pub fn record(&mut self, access: FieldAccess) {
        self.accesses.push(access);
    }

    /// Record many accesses.
    pub fn record_many(&mut self, accesses: impl IntoIterator<Item = FieldAccess>) {
        self.accesses.extend(accesses);
    }

    /// Analyse the evidence and return all union candidates, sorted by
    /// `(base_var, offset)`.
    ///
    /// A candidate is reported when the same `(base_var, offset)` pair is
    /// accessed with at least `min_distinct_widths` different widths, or when
    /// float and integer type hints disagree at the same offset.
    #[must_use]
    pub fn detect(&self) -> Vec<UnionCandidate> {
        // (base_var, offset) → accesses
        let mut by_site: BTreeMap<(u32, i64), Vec<&FieldAccess>> = BTreeMap::new();
        for a in &self.accesses {
            by_site.entry((a.base_var, a.offset)).or_default().push(a);
        }

        let mut out = Vec::new();
        for ((base_var, offset), accs) in &by_site {
            if accs.len() < self.config.min_evidence {
                continue;
            }
            let mut widths: Vec<u32> = accs.iter().map(|a| a.access_bytes).collect();
            widths.sort_unstable();
            widths.dedup();

            let has_float = accs.iter().any(|a| {
                matches!(
                    a.type_hint,
                    Some(DecompType::Float32 | DecompType::Float64)
                )
            });
            let has_int = accs.iter().any(|a| {
                matches!(a.type_hint, Some(DecompType::Int(_)))
            });
            let mixed = has_float && has_int;

            if widths.len() < self.config.min_distinct_widths && !mixed {
                continue;
            }

            let total_size = widths.last().copied().unwrap_or(0);
            let evidence_count = accs.len();
            // Confidence: more distinct widths and mixed scalar classes raise
            // it; capped at 0.95 (static evidence is never certain).
            let mut confidence =
                0.4 + 0.15 * (widths.len().saturating_sub(1) as f64);
            if mixed {
                confidence += 0.2;
            }
            confidence += (evidence_count.min(10) as f64) * 0.02;
            let confidence = confidence.min(0.95);

            out.push(UnionCandidate {
                base_var: *base_var,
                offset: *offset,
                widths,
                total_size,
                mixed_scalar_class: mixed,
                evidence_count,
                confidence,
            });
        }
        out
    }

    /// Detect unions only for one base variable.
    #[must_use]
    pub fn detect_for(&self, base_var: u32) -> Vec<UnionCandidate> {
        self.detect()
            .into_iter()
            .filter(|c| c.base_var == base_var)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn different_widths_same_offset_is_union() {
        let mut d = UnionDetector::with_defaults();
        d.record(FieldAccess::read(1, 8, 4, 0x1000));
        d.record(FieldAccess::read(1, 8, 8, 0x1010));
        let cands = d.detect();
        assert_eq!(cands.len(), 1);
        let c = &cands[0];
        assert_eq!(c.base_var, 1);
        assert_eq!(c.offset, 8);
        assert_eq!(c.widths, vec![4, 8]);
        assert_eq!(c.total_size, 8);
        assert!(!c.mixed_scalar_class);
    }

    #[test]
    fn uniform_width_is_not_union() {
        let mut d = UnionDetector::with_defaults();
        d.record(FieldAccess::read(1, 0, 4, 0x1));
        d.record(FieldAccess::write(1, 0, 4, 0x2));
        d.record(FieldAccess::read(1, 0, 4, 0x3));
        assert!(d.detect().is_empty());
    }

    #[test]
    fn mixed_float_int_hints_is_union_even_same_width() {
        let mut d = UnionDetector::with_defaults();
        d.record(
            FieldAccess::read(2, 16, 4, 0x1).with_hint(DecompType::Float32),
        );
        d.record(
            FieldAccess::read(2, 16, 4, 0x2)
                .with_hint(DecompType::Int(IntWidth::I32)),
        );
        let cands = d.detect();
        assert_eq!(cands.len(), 1);
        assert!(cands[0].mixed_scalar_class);
        assert!(cands[0].confidence > 0.5);
    }

    #[test]
    fn single_access_below_min_evidence() {
        let mut d = UnionDetector::with_defaults();
        d.record(FieldAccess::read(1, 0, 4, 0x1));
        assert!(d.detect().is_empty());
    }

    #[test]
    fn separate_offsets_not_merged() {
        let mut d = UnionDetector::with_defaults();
        d.record(FieldAccess::read(1, 0, 4, 0x1));
        d.record(FieldAccess::read(1, 8, 8, 0x2));
        assert!(d.detect().is_empty());
    }

    #[test]
    fn detect_for_filters_by_base() {
        let mut d = UnionDetector::with_defaults();
        d.record(FieldAccess::read(1, 0, 4, 0x1));
        d.record(FieldAccess::read(1, 0, 8, 0x2));
        d.record(FieldAccess::read(2, 0, 4, 0x3));
        d.record(FieldAccess::read(2, 0, 2, 0x4));
        assert_eq!(d.detect().len(), 2);
        assert_eq!(d.detect_for(1).len(), 1);
        assert_eq!(d.detect_for(1)[0].base_var, 1);
    }

    #[test]
    fn to_union_type_members_and_size() {
        let mut d = UnionDetector::with_defaults();
        d.record(FieldAccess::read(3, 4, 2, 0x1));
        d.record(FieldAccess::read(3, 4, 4, 0x2));
        d.record(FieldAccess::read(3, 4, 8, 0x3));
        let cands = d.detect();
        assert_eq!(cands.len(), 1);
        let u = cands[0].to_union_type();
        assert_eq!(u.members.len(), 3);
        assert_eq!(u.total_size, 8);
        assert!(u.member_named("as_u16").is_some());
        assert!(u.member_named("as_u32").is_some());
        assert!(u.member_named("as_u64").is_some());
        // All members at offset 0.
        assert!(u.members.iter().all(|m| m.offset == 0));
    }

    #[test]
    fn confidence_capped() {
        let mut d = UnionDetector::with_defaults();
        for i in 0..50u64 {
            let w = [1u32, 2, 4, 8][usize::try_from(i % 4).unwrap()];
            d.record(
                FieldAccess::read(1, 0, w, i).with_hint(if i % 2 == 0 {
                    DecompType::Float32
                } else {
                    DecompType::Int(IntWidth::I32)
                }),
            );
        }
        let cands = d.detect();
        assert_eq!(cands.len(), 1);
        assert!(cands[0].confidence <= 0.95);
    }
}
