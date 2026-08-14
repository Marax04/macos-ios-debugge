//! Bridge: resolve leftover `Unknown` types using `rustre-analysis-type`'s
//! attribute facts.
//!
//! # Why this exists
//!
//! Type recovery in this workspace is split across two crates that solve
//! **different halves** of the problem and, until this module, barely spoke to
//! each other — `rustre-analysis-typerecov` declared a dependency on
//! `rustre-analysis-type` and used it for exactly one symbol.
//!
//! | crate | constraint kind | solver |
//! |---|---|---|
//! | `typerecov` (here) | **relational** — `Equal`, `FieldAccess`, `IsPointerTo`, `PointerArithmetic`, `IsReturnOf` | union-find ([`crate::TypeUnifier`]) |
//! | `type` | **attribute** — `HasSize`, `IsSigned`, `IsUnsigned`, `IsFloat`, `IsArray`, `IsPointer` | refinement lattice |
//!
//! The vocabularies are **disjoint**. Unification can prove "a and b are the
//! same type" but has no notion of signedness, float-ness or byte width;
//! the attribute side knows "this is a signed 4-byte quantity" but nothing
//! about equality or field access. Neither can do the other's job, which is
//! why the fix is to connect them rather than to collapse one into the other.
//!
//! # The rule this module follows: FILL, NEVER OVERRIDE
//!
//! An attribute fact is only ever applied to a variable whose unified type came
//! out [`RecoveredType::Unknown`]. A type the unifier *did* resolve rests on
//! structural evidence and is never rewritten from an attribute hint.
//! Disagreements are therefore not silently "resolved" in favour of the newer
//! information — they are reported via [`Refinement::conflicts`] so a caller
//! can see that the two halves disagree instead of being handed a confident
//! answer built on a contradiction.

use std::collections::BTreeMap;

use rustre_analysis_type::constraints::{ConstraintFact, VarRef};
use rustre_analysis_type::lattice::{RefinementCell, TypeClass, TypeLevel};
use rustre_analysis_type::TypeFact;

use crate::{RecoveredType, TypeVar, UnificationResult};

/// Outcome of a refinement pass.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Refinement {
    /// Variables that were `Unknown` and now carry a type, with what they became.
    pub resolved: BTreeMap<TypeVar, RecoveredType>,
    /// Facts that contradict an ALREADY-resolved unification result.
    ///
    /// Not applied. Their existence means the relational and attribute halves
    /// disagree about the same variable, which is a finding in itself.
    pub conflicts: Vec<(TypeVar, RecoveredType, RecoveredType)>,
}

impl Refinement {
    /// How many previously-unresolved variables this pass recovered.
    #[must_use]
    pub fn resolved_count(&self) -> usize {
        self.resolved.len()
    }
}

/// Attributes gathered for one variable before deciding a type.
///
/// Collected across ALL facts first, because the facts are individually
/// insufficient: `HasSize{4}` alone cannot distinguish `int` from `float`, and
/// `IsSigned` alone gives no width. Only the combination is decidable.
#[derive(Debug, Default, Clone, Copy)]
struct Attrs {
    size: Option<u8>,
    signed: Option<bool>,
    is_float: bool,
    pointee_size: Option<Option<u8>>,
    array_elem: Option<(u8, Option<usize>)>,
    /// Set when two facts of the SAME kind disagree (e.g. `HasSize{4}` and
    /// `HasSize{8}` for one variable). Accumulation is last-write per field,
    /// so without this flag the later fact would silently win and `decide`
    /// would hand back a confident type built on a contradiction — the exact
    /// failure mode this module exists to avoid.
    contradictory: bool,
}

impl Attrs {
    /// Set an `Option` attribute, flagging a contradiction instead of
    /// overwriting when a different value was already recorded.
    fn set_or_conflict<T: PartialEq>(slot: &mut Option<T>, value: T, contradictory: &mut bool) {
        match slot {
            Some(existing) if *existing != value => *contradictory = true,
            _ => *slot = Some(value),
        }
    }
    /// Fold every piece of evidence into `rustre-analysis-type`'s refinement
    /// lattice and read back the result.
    ///
    /// **This deliberately delegates instead of deciding.** An earlier version
    /// of this function was a hand-rolled if/else priority chain, and the
    /// lattice is strictly better in two ways that matter:
    ///
    /// * It has a real state for *partial* knowledge — `TypeLevel::Width(n)`
    ///   ("we know only the byte width") — instead of collapsing "not enough
    ///   evidence" into a failure.
    /// * It resolves disagreement by algebra rather than by whichever branch
    ///   happened to be written first. Concretely: `HasSize(4)` + `IsFloat` +
    ///   `IsSigned` used to silently yield `float` because the float branch was
    ///   tested earlier; `meet` correctly yields `Conflict`, because those
    ///   observations genuinely contradict each other.
    ///
    /// Returns `None` when the evidence does not reach a concrete type — which
    /// includes both "too little" (`Top`/`Width`) and "contradictory"
    /// (`Conflict`). Neither may be turned into a guess.
    fn decide(self) -> Option<RecoveredType> {
        // Same-kind facts that disagreed are a contradiction; per the module
        // rule, contradictory evidence resolves nothing.
        if self.contradictory {
            return None;
        }
        let mut cell = RefinementCell::new();

        if let Some(size) = self.size {
            cell.observe(&TypeLevel::Width(usize::from(size)));
        }
        // Structural evidence is concrete, so it enters as a full fact.
        if let Some((elem_size, bound)) = self.array_elem {
            let element = Box::new(TypeFact::UnsignedInt(usize::from(elem_size)));
            // No recovered bound ⇒ a pointer to the element, NOT an array with
            // an invented length.
            cell.observe_fact(&match bound {
                Some(n) => TypeFact::Array { element, length: Some(n) },
                None => TypeFact::Pointer(element),
            });
        }
        if let Some(pointee) = self.pointee_size {
            let inner = pointee
                .map_or(TypeFact::Unknown, |sz| TypeFact::UnsignedInt(usize::from(sz)));
            cell.observe_fact(&TypeFact::Pointer(Box::new(inner)));
        }
        // Scalar class evidence needs a width to be expressible in the lattice;
        // without one it adds nothing, so it is not observed at all rather than
        // observed as a guessed width.
        if self.is_float && let Some(w) = self.size {
            cell.observe(&TypeLevel::Class(TypeClass::Float(usize::from(w))));
        }
        if let (Some(signed), Some(w)) = (self.signed, self.size) {
            let w = usize::from(w);
            cell.observe_fact(&if signed {
                TypeFact::SignedInt(w)
            } else {
                TypeFact::UnsignedInt(w)
            });
        }

        if cell.is_conflict() {
            return None;
        }
        to_recovered(&cell.recovered())
    }
}

/// Map the lattice's `TypeFact` onto this crate's `RecoveredType`.
///
/// `None` for anything that is not a concrete type — `Unknown`, and the
/// width-only `Sized(_)` level, which says "n bytes" without saying of what.
fn to_recovered(fact: &TypeFact) -> Option<RecoveredType> {
    Some(match fact {
        TypeFact::SignedInt(w) => RecoveredType::Int { width: u8::try_from(*w).ok()?, signed: true },
        TypeFact::UnsignedInt(w) => {
            RecoveredType::Int { width: u8::try_from(*w).ok()?, signed: false }
        }
        TypeFact::Float(w) => RecoveredType::Float { width: u8::try_from(*w).ok()? },
        TypeFact::Bool => RecoveredType::Int { width: 1, signed: false },
        TypeFact::Char => RecoveredType::Int { width: 1, signed: true },
        TypeFact::Pointer(inner) => RecoveredType::Pointer(Box::new(
            to_recovered(inner).unwrap_or(RecoveredType::Unknown),
        )),
        TypeFact::Array { element, length } => {
            let element = Box::new(to_recovered(element).unwrap_or(RecoveredType::Unknown));
            match length {
                Some(count) => RecoveredType::Array { element, count: *count },
                None => RecoveredType::Pointer(element),
            }
        }
        // `Sized(n)` is width-only and `Unknown`/`Struct` carry no scalar type
        // this bridge can commit to.
        TypeFact::Sized(_) | TypeFact::Unknown | TypeFact::Struct { .. } => return None,
    })
}

/// Refine `result` in place using `facts`.
///
/// `var_of` maps the attribute side's [`VarRef`] onto this crate's [`TypeVar`];
/// the caller owns that correspondence because only it knows how the two
/// analyses enumerated the same program. Facts whose variable does not map are
/// skipped rather than guessed at.
pub fn refine_unknowns(
    result: &mut UnificationResult,
    facts: &[ConstraintFact],
    var_of: impl Fn(VarRef) -> Option<TypeVar>,
) -> Refinement {
    // Pass 1: accumulate attributes per type variable.
    let mut attrs: BTreeMap<TypeVar, Attrs> = BTreeMap::new();
    let mut note = |var: VarRef, f: &dyn Fn(&mut Attrs)| {
        if let Some(tv) = var_of(var) {
            f(attrs.entry(tv).or_default());
        }
    };
    for fact in facts {
        match *fact {
            ConstraintFact::HasSize { var, size } => note(var, &move |a| {
                Attrs::set_or_conflict(&mut a.size, size, &mut a.contradictory);
            }),
            ConstraintFact::IsSigned { var } => note(var, &|a| {
                Attrs::set_or_conflict(&mut a.signed, true, &mut a.contradictory);
            }),
            ConstraintFact::IsUnsigned { var } => note(var, &|a| {
                Attrs::set_or_conflict(&mut a.signed, false, &mut a.contradictory);
            }),
            ConstraintFact::IsFloat { var } => note(var, &|a| a.is_float = true),
            ConstraintFact::IsPointer { var, pointee_size } => {
                note(var, &move |a| {
                    Attrs::set_or_conflict(&mut a.pointee_size, pointee_size, &mut a.contradictory);
                });
            }
            ConstraintFact::IsArray { var, elem_size, bound } => {
                note(var, &move |a| {
                    Attrs::set_or_conflict(&mut a.array_elem, (elem_size, bound), &mut a.contradictory);
                });
            }
            // Struct/vtable/call facts describe layout and interprocedural
            // shape rather than a scalar type; they are outside this bridge.
            _ => {}
        }
    }

    // Pass 2: apply, filling only what the unifier left Unknown.
    let mut out = Refinement::default();
    for (tv, a) in attrs {
        let Some(decided) = a.decide() else { continue };
        match result.types.get(&tv) {
            Some(RecoveredType::Unknown) | None => {
                result.types.insert(tv, decided.clone());
                out.resolved.insert(tv, decided);
            }
            Some(existing) if *existing != decided => {
                out.conflicts.push((tv, existing.clone(), decided));
            }
            Some(_) => {}
        }
    }

    // Keep the reported `unresolved` list consistent with what we just filled.
    result.unresolved.retain(|tv| !out.resolved.contains_key(tv));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unified(pairs: &[(u32, RecoveredType)]) -> UnificationResult {
        let types: std::collections::BTreeMap<TypeVar, RecoveredType> =
            pairs.iter().map(|(i, t)| (TypeVar::new(*i), t.clone())).collect();
        let unresolved = types
            .iter()
            .filter(|(_, t)| matches!(t, RecoveredType::Unknown))
            .map(|(v, _)| *v)
            .collect();
        UnificationResult { types, class_count: pairs.len(), unresolved }
    }

    fn v(i: u32) -> VarRef {
        VarRef::new(0, i)
    }

    fn ident(r: VarRef) -> Option<TypeVar> {
        Some(TypeVar::new(r.index))
    }

    #[test]
    fn size_plus_signedness_resolves_an_unknown() {
        let mut res = unified(&[(0, RecoveredType::Unknown)]);
        assert_eq!(res.unresolved.len(), 1);
        let facts = [
            ConstraintFact::HasSize { var: v(0), size: 4 },
            ConstraintFact::IsSigned { var: v(0) },
        ];
        let r = refine_unknowns(&mut res, &facts, ident);
        assert_eq!(r.resolved_count(), 1);
        assert_eq!(res.types[&TypeVar::new(0)], RecoveredType::Int { width: 4, signed: true });
        assert!(res.unresolved.is_empty(), "the unresolved list must stay consistent");
    }

    #[test]
    fn size_alone_is_not_enough_and_must_not_guess() {
        // 4 bytes could be int or float. Guessing is how confidently-wrong
        // output gets created, so the variable stays Unknown.
        let mut res = unified(&[(0, RecoveredType::Unknown)]);
        let facts = [ConstraintFact::HasSize { var: v(0), size: 4 }];
        let r = refine_unknowns(&mut res, &facts, ident);
        assert_eq!(r.resolved_count(), 0);
        assert_eq!(res.types[&TypeVar::new(0)], RecoveredType::Unknown);
    }

    #[test]
    fn a_resolved_type_is_never_overridden() {
        let mut res = unified(&[(0, RecoveredType::Int { width: 8, signed: false })]);
        let facts = [
            ConstraintFact::HasSize { var: v(0), size: 4 },
            ConstraintFact::IsSigned { var: v(0) },
        ];
        let r = refine_unknowns(&mut res, &facts, ident);
        assert_eq!(r.resolved_count(), 0, "must not overwrite unification evidence");
        assert_eq!(res.types[&TypeVar::new(0)], RecoveredType::Int { width: 8, signed: false });
        assert_eq!(r.conflicts.len(), 1, "the disagreement must be REPORTED, not hidden");
    }

    #[test]
    fn float_resolves_when_the_evidence_agrees() {
        let mut res = unified(&[(0, RecoveredType::Unknown)]);
        let facts =
            [ConstraintFact::HasSize { var: v(0), size: 8 }, ConstraintFact::IsFloat { var: v(0) }];
        refine_unknowns(&mut res, &facts, ident);
        assert_eq!(res.types[&TypeVar::new(0)], RecoveredType::Float { width: 8 });
    }

    #[test]
    fn float_and_signed_int_together_are_a_conflict_not_a_winner() {
        // "It is a float" and "it is a signed integer" are contradictory claims
        // about the same variable. This test previously asserted that float
        // WON — which was only true because the old hand-rolled decision tested
        // the float branch first. Delegating to the lattice makes `meet` report
        // `Conflict`, and the honest answer to contradictory evidence is to
        // resolve nothing rather than to pick the branch written earliest.
        let mut res = unified(&[(0, RecoveredType::Unknown)]);
        let facts = [
            ConstraintFact::HasSize { var: v(0), size: 8 },
            ConstraintFact::IsFloat { var: v(0) },
            ConstraintFact::IsSigned { var: v(0) },
        ];
        let r = refine_unknowns(&mut res, &facts, ident);
        assert_eq!(r.resolved_count(), 0, "contradictory evidence must resolve nothing");
        assert_eq!(res.types[&TypeVar::new(0)], RecoveredType::Unknown);
    }

    #[test]
    fn array_without_a_bound_becomes_a_pointer_not_a_fabricated_array() {
        let mut res = unified(&[(0, RecoveredType::Unknown)]);
        let facts = [ConstraintFact::IsArray { var: v(0), elem_size: 4, bound: None }];
        refine_unknowns(&mut res, &facts, ident);
        match &res.types[&TypeVar::new(0)] {
            RecoveredType::Pointer(_) => {}
            other => panic!("expected a pointer, got {other:?}"),
        }
    }

    /// Two `HasSize` facts that disagree are a contradiction. The old code
    /// accumulated attributes last-write-wins, so `HasSize{4}, HasSize{8},
    /// IsSigned` confidently resolved `Int{width:8, signed:true}` — a type
    /// built on evidence the module KNEW was self-contradictory.
    #[test]
    fn conflicting_sizes_resolve_nothing() {
        let mut res = unified(&[(0, RecoveredType::Unknown)]);
        let facts = [
            ConstraintFact::HasSize { var: v(0), size: 4 },
            ConstraintFact::HasSize { var: v(0), size: 8 },
            ConstraintFact::IsSigned { var: v(0) },
        ];
        let r = refine_unknowns(&mut res, &facts, ident);
        assert_eq!(r.resolved_count(), 0, "conflicting sizes must not resolve");
        assert_eq!(res.types[&TypeVar::new(0)], RecoveredType::Unknown);
    }

    /// `IsSigned` + `IsUnsigned` on the same variable previously let the
    /// LATER fact win (order-dependent, silently). Both orders must resolve
    /// nothing.
    #[test]
    fn conflicting_signedness_resolves_nothing_in_either_order() {
        for flip in [false, true] {
            let mut res = unified(&[(0, RecoveredType::Unknown)]);
            let (a, b) = if flip {
                (ConstraintFact::IsUnsigned { var: v(0) }, ConstraintFact::IsSigned { var: v(0) })
            } else {
                (ConstraintFact::IsSigned { var: v(0) }, ConstraintFact::IsUnsigned { var: v(0) })
            };
            let facts = [ConstraintFact::HasSize { var: v(0), size: 4 }, a, b];
            let r = refine_unknowns(&mut res, &facts, ident);
            assert_eq!(r.resolved_count(), 0, "flip={flip}: signedness conflict must not resolve");
            assert_eq!(res.types[&TypeVar::new(0)], RecoveredType::Unknown);
        }
    }

    /// A REPEATED identical fact is agreement, not a conflict.
    #[test]
    fn duplicate_identical_facts_still_resolve() {
        let mut res = unified(&[(0, RecoveredType::Unknown)]);
        let facts = [
            ConstraintFact::HasSize { var: v(0), size: 4 },
            ConstraintFact::HasSize { var: v(0), size: 4 },
            ConstraintFact::IsSigned { var: v(0) },
        ];
        let r = refine_unknowns(&mut res, &facts, ident);
        assert_eq!(r.resolved_count(), 1);
        assert_eq!(res.types[&TypeVar::new(0)], RecoveredType::Int { width: 4, signed: true });
    }

    #[test]
    fn unmapped_vars_are_skipped_not_guessed() {
        let mut res = unified(&[(0, RecoveredType::Unknown)]);
        let facts = [
            ConstraintFact::HasSize { var: v(0), size: 4 },
            ConstraintFact::IsSigned { var: v(0) },
        ];
        let r = refine_unknowns(&mut res, &facts, |_| None);
        assert_eq!(r.resolved_count(), 0);
        assert_eq!(res.types[&TypeVar::new(0)], RecoveredType::Unknown);
    }
}
