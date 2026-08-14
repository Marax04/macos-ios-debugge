//! Multi-level type-recovery lattice and constraint refinement.
//!
//! Decompiler type recovery proceeds by *refinement*: facts start at the top of
//! a lattice (`Unknown`/`Top`) and are progressively narrowed as evidence
//! accumulates, while contradictory evidence widens back toward `Top`.  This
//! module layers a principled lattice on top of the existing [`TypeFact`]
//! domain so that the analysis side (this crate) can reason about *specificity*
//! independently of the decompiler-side type system.
//!
//! The lattice has four conceptual levels, from least to most specific:
//!
//! ```text
//!   Top  (Unknown)
//!    │
//!   width-only  (Sized(n))            ── we know it occupies n bytes
//!    │
//!   class       (integer / float / pointer / bool / char)
//!    │
//!   concrete    (i32, u64, *T, struct{…})
//!    │
//!   Bottom  (Conflict)               ── contradictory evidence
//! ```

use crate::TypeFact;

/// A point in the multi-level type lattice.
///
/// The seven recovery levels (§6.6) from least to most specific:
///
/// 1. `Width`            — sized variables (byte-width only)
/// 2. `Class`            — primitive type class (int / float / ptr / bool / char)
/// 3. `Concrete`         — fully concrete pointer or primitive type
/// 4. `Concrete(Struct)` — struct inference (fields recovered from accesses)
/// 5. `Concrete(Array)`  — array inference (element type + optional length)
/// 6. `Concrete(Vtable)` — class / vtable recovery
/// 7. `LibrarySignature` — library function signature (FLIRT / import table)
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TypeLevel {
    /// Top: nothing known.
    Top,
    /// Level 1 — We know only the byte width.
    Width(usize),
    /// Level 2 — We know the broad class but not the exact type.
    Class(TypeClass),
    /// Levels 3–6 — We have a fully concrete type fact.
    Concrete(TypeFact),
    /// Level 7 — Type is fully resolved from a library function signature
    /// (FLIRT match or import-table entry).  This is the most specific level
    /// below `Conflict` because it carries both parameter and return-value
    /// information derived from a known ABI.
    LibrarySignature,
    /// Contradictory evidence: irreconcilable observations.
    Conflict,
}

/// The broad type class, the lattice's middle tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TypeClass {
    /// Signed or unsigned integer of `width` bytes.
    Integer(usize),
    /// Floating-point of `width` bytes.
    Float(usize),
    /// Pointer (width is the architecture pointer size).
    Pointer(usize),
    /// Boolean.
    Boolean,
    /// Character.
    Character,
    /// Aggregate (struct/array) of `width` bytes.
    Aggregate(usize),
}

impl TypeClass {
    /// Byte width associated with this class, if any.
    #[must_use]
    pub const fn width(self) -> Option<usize> {
        match self {
            Self::Integer(w) | Self::Float(w) | Self::Pointer(w) | Self::Aggregate(w) => Some(w),
            Self::Boolean | Self::Character => Some(1),
        }
    }
}

impl TypeLevel {
    /// The lattice rank: higher is more specific.  Used only for ordering, not
    /// as a join — `join`/`meet` perform structural reasoning.
    ///
    /// Ranks map directly to the seven recovery levels:
    ///
    /// | Rank | Level                             |
    /// |------|-----------------------------------|
    /// |  0   | Top (unknown)                     |
    /// |  1   | Width (sized variable)            |
    /// |  2   | Class (primitive class)           |
    /// |  3   | Concrete (pointer / prim / struct)|
    /// |  4   | LibrarySignature                  |
    /// |  5   | Conflict                          |
    #[must_use]
    pub const fn specificity(&self) -> u8 {
        match self {
            Self::Top => 0,
            Self::Width(_) => 1,
            Self::Class(_) => 2,
            Self::Concrete(_) => 3,
            Self::LibrarySignature => 4,
            Self::Conflict => 5,
        }
    }

    /// Classify a [`TypeFact`] into its lattice level.
    #[must_use]
    pub fn from_fact(fact: &TypeFact) -> Self {
        match fact {
            TypeFact::Unknown => Self::Top,
            TypeFact::Sized(n) => Self::Width(*n),
            TypeFact::SignedInt(n) | TypeFact::UnsignedInt(n) => {
                Self::Concrete(fact_with_width(fact, *n))
            }
            TypeFact::Float(_)
            | TypeFact::Bool
            | TypeFact::Char
            | TypeFact::Pointer(_)
            | TypeFact::Array { .. }
            | TypeFact::Struct { .. } => Self::Concrete(fact.clone()),
        }
    }

    /// Derive the broad class of a concrete fact.
    #[must_use]
    pub fn class_of(fact: &TypeFact) -> Option<TypeClass> {
        match fact {
            TypeFact::SignedInt(n) | TypeFact::UnsignedInt(n) => Some(TypeClass::Integer(*n)),
            TypeFact::Float(n) => Some(TypeClass::Float(*n)),
            TypeFact::Pointer(_) => Some(TypeClass::Pointer(8)),
            TypeFact::Bool => Some(TypeClass::Boolean),
            TypeFact::Char => Some(TypeClass::Character),
            TypeFact::Array { .. } | TypeFact::Struct { .. } => {
                fact.byte_size().map(TypeClass::Aggregate)
            }
            _ => None,
        }
    }

    /// Byte width implied by this level, if any.
    #[must_use]
    pub fn width(&self) -> Option<usize> {
        match self {
            Self::Top | Self::Conflict | Self::LibrarySignature => None,
            Self::Width(n) => Some(*n),
            Self::Class(c) => c.width(),
            Self::Concrete(f) => f.byte_size(),
        }
    }

    /// Whether `self` is at least as specific as `other` (i.e. `self ⊑ other` in
    /// the refinement order where Bottom/Conflict is most specific).
    #[must_use]
    pub const fn refines(&self, other: &Self) -> bool {
        self.specificity() >= other.specificity()
    }

    /// The lattice **meet** (greatest lower bound): combine two observations of
    /// the same variable, keeping the most specific consistent information.
    /// Inconsistent widths or classes collapse to [`TypeLevel::Conflict`].
    #[must_use]
    pub fn meet(&self, other: &Self) -> Self {
        match (self, other) {
            (Self::Conflict, _) | (_, Self::Conflict) => Self::Conflict,
            (Self::Top, x) | (x, Self::Top) => x.clone(),
            // LibrarySignature is the most specific non-conflict level;
            // meeting it with anything less specific keeps it.
            (Self::LibrarySignature, _) | (_, Self::LibrarySignature) => Self::LibrarySignature,
            (Self::Width(a), Self::Width(b)) => {
                if a == b {
                    Self::Width(*a)
                } else {
                    Self::Conflict
                }
            }
            // A width meets a more specific level only if the widths agree.
            (Self::Width(w), other_lvl) | (other_lvl, Self::Width(w)) => match other_lvl.width() {
                Some(ow) if ow == *w => other_lvl.clone(),
                Some(_) => Self::Conflict,
                None => other_lvl.clone(),
            },
            (Self::Class(a), Self::Class(b)) => {
                if a == b {
                    Self::Class(*a)
                } else {
                    Self::Conflict
                }
            }
            (Self::Class(c), Self::Concrete(f)) | (Self::Concrete(f), Self::Class(c)) => {
                match Self::class_of(f) {
                    Some(fc) if fc == *c => Self::Concrete(f.clone()),
                    _ => Self::Conflict,
                }
            }
            (Self::Concrete(a), Self::Concrete(b)) => {
                if a == b {
                    Self::Concrete(a.clone())
                } else {
                    // Try structural join of the facts (e.g. *? and *i32 -> *i32).
                    let j = a.join(b);
                    if j.is_known() && (j == *a || j == *b) {
                        Self::Concrete(j)
                    } else {
                        Self::Conflict
                    }
                }
            }
        }
    }

    /// The lattice **join** (least upper bound): generalise two observations to
    /// the most specific level they both satisfy.  Never produces a conflict.
    #[must_use]
    pub fn join(&self, other: &Self) -> Self {
        // Idempotence: `x ⊔ x == x`. Without this, identical `Class`/`Width`
        // levels fall through to the width-fallback below and lose precision
        // (e.g. `join(Class(Integer(4)), Class(Integer(4)))` would return
        // `Width(4)` instead of the class).
        if self == other {
            return self.clone();
        }
        match (self, other) {
            (Self::Top, _) | (_, Self::Top) => Self::Top,
            (Self::Conflict, x) | (x, Self::Conflict) => x.clone(),
            // Two library-signature levels stay at LibrarySignature.
            (Self::LibrarySignature, Self::LibrarySignature) => Self::LibrarySignature,
            // Joining LibrarySignature with anything less specific widens to Concrete
            // (we lose the library-derived precision but keep structural facts).
            (Self::LibrarySignature, Self::Concrete(f))
            | (Self::Concrete(f), Self::LibrarySignature) => Self::Concrete(f.clone()),
            (Self::LibrarySignature, other_lvl) | (other_lvl, Self::LibrarySignature) => {
                other_lvl.clone()
            }
            (Self::Concrete(a), Self::Concrete(b)) if a == b => Self::Concrete(a.clone()),
            _ => {
                // Fall back to a common class, then a common width, then Top.
                if let (Self::Concrete(a), Self::Concrete(b)) = (self, other)
                    && let (Some(ca), Some(cb)) = (Self::class_of(a), Self::class_of(b))
                    && ca == cb
                {
                    return Self::Class(ca);
                }
                match (self.width(), other.width()) {
                    (Some(wa), Some(wb)) if wa == wb => Self::Width(wa),
                    _ => Self::Top,
                }
            }
        }
    }

    /// Lower the level back to a [`TypeFact`] for export to the decompiler side.
    ///
    /// `LibrarySignature` exports as `Unknown` here because the caller should
    /// consult [`WinApiTypeDb`] / [`LibraryTypeImporter`] directly for the full
    /// structured signature; a bare `TypeFact` cannot represent a function
    /// prototype.
    #[must_use]
    pub fn to_fact(&self) -> TypeFact {
        match self {
            Self::Top | Self::Conflict | Self::LibrarySignature => TypeFact::Unknown,
            Self::Width(n) => TypeFact::Sized(*n),
            Self::Class(c) => match c {
                TypeClass::Integer(n) => TypeFact::UnsignedInt(*n),
                TypeClass::Float(n) => TypeFact::Float(*n),
                TypeClass::Pointer(_) => TypeFact::Pointer(Box::new(TypeFact::Unknown)),
                TypeClass::Boolean => TypeFact::Bool,
                TypeClass::Character => TypeFact::Char,
                TypeClass::Aggregate(n) => TypeFact::Sized(*n),
            },
            Self::Concrete(f) => f.clone(),
        }
    }
}

/// Build a concrete fact whose width is `n` from `template`'s constructor.
fn fact_with_width(template: &TypeFact, n: usize) -> TypeFact {
    match template {
        TypeFact::SignedInt(_) => TypeFact::SignedInt(n),
        TypeFact::UnsignedInt(_) => TypeFact::UnsignedInt(n),
        TypeFact::Float(_) => TypeFact::Float(n),
        other => other.clone(),
    }
}

/// A refinement cell: an accumulating type estimate for one variable that can
/// only become more specific (via `meet`) as observations arrive.
#[derive(Debug, Clone)]
pub struct RefinementCell {
    level: TypeLevel,
    observations: usize,
}

impl Default for RefinementCell {
    fn default() -> Self {
        Self {
            level: TypeLevel::Top,
            observations: 0,
        }
    }
}

impl RefinementCell {
    /// A fresh cell at `Top`.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Incorporate a new observation, narrowing the estimate via meet.
    pub fn observe(&mut self, level: &TypeLevel) {
        self.level = self.level.meet(level);
        self.observations += 1;
    }

    /// Incorporate a concrete type-fact observation.
    pub fn observe_fact(&mut self, fact: &TypeFact) {
        self.observe(&TypeLevel::from_fact(fact));
    }

    /// The current best estimate.
    #[must_use]
    pub const fn level(&self) -> &TypeLevel {
        &self.level
    }

    /// Whether the accumulated evidence is contradictory.
    #[must_use]
    pub const fn is_conflict(&self) -> bool {
        matches!(self.level, TypeLevel::Conflict)
    }

    /// Number of observations folded in.
    #[must_use]
    pub const fn observation_count(&self) -> usize {
        self.observations
    }

    /// Export the recovered type fact.
    #[must_use]
    pub fn recovered(&self) -> TypeFact {
        self.level.to_fact()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_fact_levels() {
        assert_eq!(TypeLevel::from_fact(&TypeFact::Unknown), TypeLevel::Top);
        assert_eq!(
            TypeLevel::from_fact(&TypeFact::Sized(4)),
            TypeLevel::Width(4)
        );
        assert!(matches!(
            TypeLevel::from_fact(&TypeFact::SignedInt(4)),
            TypeLevel::Concrete(_)
        ));
    }

    #[test]
    fn specificity_ordering() {
        assert!(TypeLevel::Concrete(TypeFact::SignedInt(4)).refines(&TypeLevel::Width(4)));
        assert!(TypeLevel::Width(4).refines(&TypeLevel::Top));
        assert!(!TypeLevel::Top.refines(&TypeLevel::Width(4)));
    }

    #[test]
    fn meet_width_consistent() {
        let a = TypeLevel::Width(4);
        let b = TypeLevel::Concrete(TypeFact::SignedInt(4));
        // meeting a 4-byte width with a 4-byte int keeps the int.
        assert_eq!(a.meet(&b), TypeLevel::Concrete(TypeFact::SignedInt(4)));
    }

    #[test]
    fn meet_width_conflict() {
        let a = TypeLevel::Width(4);
        let b = TypeLevel::Concrete(TypeFact::SignedInt(8));
        assert_eq!(a.meet(&b), TypeLevel::Conflict);
    }

    #[test]
    fn meet_top_is_identity() {
        let b = TypeLevel::Concrete(TypeFact::Bool);
        assert_eq!(TypeLevel::Top.meet(&b), b);
    }

    #[test]
    fn meet_conflicting_concrete() {
        let a = TypeLevel::Concrete(TypeFact::SignedInt(4));
        let b = TypeLevel::Concrete(TypeFact::Float(4));
        assert_eq!(a.meet(&b), TypeLevel::Conflict);
    }

    #[test]
    fn meet_class_and_concrete() {
        let cls = TypeLevel::Class(TypeClass::Integer(4));
        let conc = TypeLevel::Concrete(TypeFact::UnsignedInt(4));
        assert_eq!(cls.meet(&conc), conc);
    }

    #[test]
    fn join_generalises_to_class() {
        let a = TypeLevel::Concrete(TypeFact::SignedInt(4));
        let b = TypeLevel::Concrete(TypeFact::UnsignedInt(4));
        // Both are integers of width 4 -> generalise to the integer class.
        assert_eq!(a.join(&b), TypeLevel::Class(TypeClass::Integer(4)));
    }

    #[test]
    fn join_generalises_to_width() {
        let a = TypeLevel::Concrete(TypeFact::SignedInt(4));
        let b = TypeLevel::Concrete(TypeFact::Float(4));
        // Different classes, same width -> width-only.
        assert_eq!(a.join(&b), TypeLevel::Width(4));
    }

    #[test]
    fn join_to_top_when_disjoint() {
        let a = TypeLevel::Concrete(TypeFact::SignedInt(4));
        let b = TypeLevel::Concrete(TypeFact::SignedInt(8));
        assert_eq!(a.join(&b), TypeLevel::Top);
    }

    /// join must be idempotent: `x ⊔ x == x` for every level. Previously
    /// `join(Class(c), Class(c))` fell through to the width-fallback and
    /// returned `Width(c.width())`, losing the class (an idempotency +
    /// precision bug).
    #[test]
    fn join_is_idempotent() {
        let levels = [
            TypeLevel::Top,
            TypeLevel::Conflict,
            TypeLevel::LibrarySignature,
            TypeLevel::Width(4),
            TypeLevel::Class(TypeClass::Integer(4)),
            TypeLevel::Class(TypeClass::Float(8)),
            TypeLevel::Concrete(TypeFact::SignedInt(4)),
        ];
        for lvl in &levels {
            assert_eq!(&lvl.join(lvl), lvl, "join not idempotent for {lvl:?}");
        }
    }

    #[test]
    fn refinement_cell_narrows() {
        let mut cell = RefinementCell::new();
        assert_eq!(cell.level(), &TypeLevel::Top);
        cell.observe(&TypeLevel::Width(4));
        assert_eq!(cell.level(), &TypeLevel::Width(4));
        cell.observe_fact(&TypeFact::SignedInt(4));
        assert_eq!(cell.recovered(), TypeFact::SignedInt(4));
        assert_eq!(cell.observation_count(), 2);
        assert!(!cell.is_conflict());
    }

    #[test]
    fn refinement_cell_detects_conflict() {
        let mut cell = RefinementCell::new();
        cell.observe_fact(&TypeFact::SignedInt(4));
        cell.observe_fact(&TypeFact::Float(8));
        assert!(cell.is_conflict());
        assert_eq!(cell.recovered(), TypeFact::Unknown);
    }

    #[test]
    fn to_fact_roundtrip_for_class() {
        let lvl = TypeLevel::Class(TypeClass::Pointer(8));
        assert!(matches!(lvl.to_fact(), TypeFact::Pointer(_)));
    }

    #[test]
    fn pointer_meet_refines_pointee() {
        // *? meets *i32 -> *i32.
        let a = TypeLevel::Concrete(TypeFact::Pointer(Box::new(TypeFact::Unknown)));
        let b = TypeLevel::Concrete(TypeFact::Pointer(Box::new(TypeFact::SignedInt(4))));
        assert_eq!(
            a.meet(&b),
            TypeLevel::Concrete(TypeFact::Pointer(Box::new(TypeFact::SignedInt(4))))
        );
    }

    // ── Additional edge-case tests ───────────────────────────────────────────

    #[test]
    fn specificity_orders_levels() {
        assert_eq!(TypeLevel::Top.specificity(), 0);
        assert_eq!(TypeLevel::Width(4).specificity(), 1);
        assert_eq!(TypeLevel::Class(TypeClass::Boolean).specificity(), 2);
        assert_eq!(TypeLevel::Concrete(TypeFact::Bool).specificity(), 3);
        assert_eq!(TypeLevel::LibrarySignature.specificity(), 4);
        assert_eq!(TypeLevel::Conflict.specificity(), 5);
        assert!(TypeLevel::Conflict.refines(&TypeLevel::Top));
        assert!(!TypeLevel::Top.refines(&TypeLevel::Conflict));
    }

    #[test]
    fn type_class_width_defaults() {
        assert_eq!(TypeClass::Integer(4).width(), Some(4));
        assert_eq!(TypeClass::Float(8).width(), Some(8));
        assert_eq!(TypeClass::Boolean.width(), Some(1));
        assert_eq!(TypeClass::Character.width(), Some(1));
        assert_eq!(TypeClass::Aggregate(16).width(), Some(16));
        assert_eq!(TypeClass::Pointer(8).width(), Some(8));
    }

    #[test]
    fn meet_with_conflict_or_top() {
        let any = TypeLevel::Width(4);
        assert_eq!(TypeLevel::Conflict.meet(&any), TypeLevel::Conflict);
        assert_eq!(any.meet(&TypeLevel::Conflict), TypeLevel::Conflict);
        assert_eq!(TypeLevel::Top.meet(&any), any);
        assert_eq!(any.meet(&TypeLevel::Top), any);
    }

    #[test]
    fn meet_width_conflict_on_mismatch() {
        let a = TypeLevel::Width(4);
        let b = TypeLevel::Width(8);
        assert_eq!(a.meet(&b), TypeLevel::Conflict);
        let c = TypeLevel::Width(4);
        assert_eq!(a.meet(&c), TypeLevel::Width(4));
    }

    #[test]
    fn join_widens_to_top_for_disjoint() {
        let a = TypeLevel::Concrete(TypeFact::Bool);
        let b = TypeLevel::Concrete(TypeFact::Float(4));
        // Disjoint classes & widths → Top.
        assert_eq!(a.join(&b), TypeLevel::Top);
    }

    #[test]
    fn join_with_top_and_conflict() {
        let any = TypeLevel::Width(4);
        assert_eq!(TypeLevel::Top.join(&any), TypeLevel::Top);
        assert_eq!(any.join(&TypeLevel::Top), TypeLevel::Top);
        // Conflict joined with anything yields the other operand.
        assert_eq!(TypeLevel::Conflict.join(&any), any);
    }

    #[test]
    fn refinement_cell_accumulates_observations() {
        let mut cell = RefinementCell::new();
        assert_eq!(cell.observation_count(), 0);
        assert!(matches!(cell.level(), TypeLevel::Top));
        cell.observe(&TypeLevel::Width(4));
        cell.observe(&TypeLevel::Class(TypeClass::Integer(4)));
        assert_eq!(cell.observation_count(), 2);
        assert!(!cell.is_conflict());
    }

    #[test]
    fn refinement_cell_detects_width_conflict() {
        let mut cell = RefinementCell::new();
        cell.observe(&TypeLevel::Width(4));
        cell.observe(&TypeLevel::Width(8));
        assert!(cell.is_conflict());
        assert_eq!(cell.recovered(), TypeFact::Unknown);
    }

    #[test]
    fn to_fact_for_each_class() {
        assert!(matches!(
            TypeLevel::Class(TypeClass::Integer(4)).to_fact(),
            TypeFact::UnsignedInt(4)
        ));
        assert!(matches!(
            TypeLevel::Class(TypeClass::Float(8)).to_fact(),
            TypeFact::Float(8)
        ));
        assert!(matches!(TypeLevel::Class(TypeClass::Boolean).to_fact(), TypeFact::Bool));
        assert!(matches!(TypeLevel::Class(TypeClass::Character).to_fact(), TypeFact::Char));
        assert!(matches!(
            TypeLevel::Class(TypeClass::Aggregate(16)).to_fact(),
            TypeFact::Sized(16)
        ));
    }
}
