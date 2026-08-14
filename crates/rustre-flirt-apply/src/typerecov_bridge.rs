//! Level 7 — feed FLIRT identifications into type recovery.
//!
//! # Why this module exists
//!
//! The multi-level type recovery in `rustre-analysis-typerecov` is documented as
//! `size → primitive → pointer → struct → array → vtable → signature`, where the
//! last level is meant to be seeded by FLIRT: once a function is *identified*,
//! its published prototype is known exactly, with no inference needed.
//!
//! That level was never wired up. `rustre-analysis-typerecov` had the socket —
//! [`register_function_signature`] — but nothing plugged FLIRT into it, so the
//! recovery pass could not benefit from a single FLIRT match. This module is
//! that plug.
//!
//! # The one rule
//!
//! **Only publish prototypes we actually know.** A FLIRT match tells us a
//! function's *name*; it does not tell us its signature. We publish a signature
//! only when that name has a published prototype in
//! [`crate::rename_propagator::builtin_signatures`], and we publish nothing at
//! all otherwise.
//!
//! This is not caution for its own sake. A wrong prototype propagates into every
//! caller's recovered types and compiles perfectly, so it is strictly worse than
//! no prototype: `strdup` emitted with a phantom second parameter corrupts every
//! call site while looking entirely healthy. Silence is a safe answer here;
//! a confident guess is not.

use std::collections::HashMap;

use rustre_analysis_typerecov::{
    register_function_signature, FunctionSignatureRecord, RecoveredType,
};

use crate::flirt_applicator::ResolvedMatch;
use crate::rename_propagator::{builtin_signatures, FunctionSignature, TypeDescriptor};
use crate::runtime_prototypes::runtime_prototypes;

// ─── Type translation ────────────────────────────────────────────────────────

/// Translate a FLIRT [`TypeDescriptor`] into a type-recovery [`RecoveredType`].
///
/// Anything the target lattice cannot express becomes [`RecoveredType::Unknown`]
/// rather than a near-miss: an approximate type is indistinguishable from a
/// recovered one downstream, so a lossy mapping would launder a guess into a
/// fact.
#[must_use]
pub fn to_recovered_type(td: &TypeDescriptor) -> RecoveredType {
    match td {
        // `void` is not a value type in the recovery lattice.
        TypeDescriptor::Void => RecoveredType::Unknown,
        // `bool` collapses onto `u8`: the recovery lattice has no boolean, and
        // a C `bool` *is* a one-byte unsigned value. Merged into one arm rather
        // than written twice, so the collapse reads as deliberate — two arms
        // with identical bodies look like an unfinished distinction, which is
        // exactly how the `strdup` prototype bug hid in this crate.
        TypeDescriptor::Bool | TypeDescriptor::U8 => {
            RecoveredType::Int { width: 1, signed: false }
        }
        TypeDescriptor::U16 => RecoveredType::Int { width: 2, signed: false },
        TypeDescriptor::U32 => RecoveredType::Int { width: 4, signed: false },
        TypeDescriptor::U64 => RecoveredType::Int { width: 8, signed: false },
        TypeDescriptor::I8 => RecoveredType::Int { width: 1, signed: true },
        TypeDescriptor::I16 => RecoveredType::Int { width: 2, signed: true },
        TypeDescriptor::I32 => RecoveredType::Int { width: 4, signed: true },
        TypeDescriptor::I64 => RecoveredType::Int { width: 8, signed: true },
        TypeDescriptor::F32 => RecoveredType::Float { width: 4 },
        TypeDescriptor::F64 => RecoveredType::Float { width: 8 },
        TypeDescriptor::Pointer(inner) => {
            RecoveredType::Pointer(Box::new(to_recovered_type(inner)))
        }
        TypeDescriptor::Array { elem, count } => RecoveredType::Array {
            element: Box::new(to_recovered_type(elem)),
            count: *count,
        },
        TypeDescriptor::Struct(name) => RecoveredType::Struct { name: name.clone() },
        TypeDescriptor::FnPtr { params, .. } => {
            RecoveredType::FnPtr { param_count: params.len() }
        }
        // `union` and `enum` have no counterpart in the recovery lattice.
        // Mapping them to `Struct` would claim a layout we do not have.
        TypeDescriptor::Union(_) | TypeDescriptor::Enum(_) | TypeDescriptor::Unknown => {
            RecoveredType::Unknown
        }
    }
}

/// Convert a known FLIRT prototype into the record type recovery consumes.
#[must_use]
pub fn to_signature_record(sig: &FunctionSignature) -> FunctionSignatureRecord {
    FunctionSignatureRecord {
        calling_convention: Some(sig.calling_convention.clone()),
        return_type: Some(to_recovered_type(&sig.return_type)),
        args: sig
            .params
            .iter()
            .map(|(name, ty)| (name.clone(), to_recovered_type(ty)))
            .collect(),
    }
}

// ─── The bridge ──────────────────────────────────────────────────────────────

/// Outcome of publishing a batch of FLIRT matches.
///
/// `skipped_unknown_prototype` is deliberately a first-class number rather than
/// a silent drop: it is the honest measure of how much of the FLIRT match set
/// this level can currently exploit.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BridgeStats {
    /// Matches considered.
    pub considered: usize,
    /// Signatures published into the type-recovery registry.
    pub published: usize,
    /// Matches whose name has no published prototype, so nothing was published.
    pub skipped_unknown_prototype: usize,
}

impl BridgeStats {
    /// Fraction of considered matches that yielded a signature, in `0.0..=1.0`.
    #[must_use]
    pub fn publish_rate(&self) -> f64 {
        if self.considered == 0 {
            return 0.0;
        }
        f64::from(u32::try_from(self.published).unwrap_or(u32::MAX))
            / f64::from(u32::try_from(self.considered).unwrap_or(u32::MAX))
    }
}

/// Index every known prototype by name, once per call.
///
/// Two sources, deliberately kept separate so provenance stays visible:
/// `builtin_signatures()` (libc + Win32, hand-curated) and
/// `runtime_prototypes()` (mingw-w64 / libgcc, mechanically extracted from the
/// installed headers). The hand-curated set wins on collision, since it is the
/// one a human has actually checked.
fn prototype_index() -> HashMap<String, FunctionSignature> {
    let mut map: HashMap<String, FunctionSignature> = runtime_prototypes()
        .into_iter()
        .map(|s| (s.name.clone(), s))
        .collect();
    for s in builtin_signatures() {
        map.insert(s.name.clone(), s);
    }
    map
}

/// Every prototype the Level 7 bridge can publish, from both sources.
#[must_use]
pub fn all_known_prototypes() -> Vec<FunctionSignature> {
    let mut v: Vec<FunctionSignature> = prototype_index().into_values().collect();
    v.sort_by(|a, b| a.name.cmp(&b.name));
    v
}

/// Number of distinct function names the Level 7 bridge can publish for.
#[must_use]
pub fn known_prototype_count() -> usize {
    prototype_index().len()
}

/// Publish `(address, name)` identifications into type recovery.
///
/// Returns [`BridgeStats`]; names without a published prototype are counted and
/// skipped, never guessed.
pub fn publish_identifications<'a, I>(ids: I) -> BridgeStats
where
    I: IntoIterator<Item = (u64, &'a str)>,
{
    let index = prototype_index();
    let mut stats = BridgeStats::default();
    for (addr, name) in ids {
        stats.considered += 1;
        if let Some(sig) = index.get(name) {
            register_function_signature(addr, to_signature_record(sig));
            stats.published += 1;
        } else {
            stats.skipped_unknown_prototype += 1;
        }
    }
    stats
}

/// Publish validated FLIRT matches into type recovery.
///
/// Convenience wrapper over [`publish_identifications`] for the applier's own
/// [`ResolvedMatch`] output.
///
/// The returned [`BridgeStats`] is the only signal that anything was published:
/// a run where every name lacked a prototype returns `published: 0` and looks
/// exactly like a successful one. Discarding it is how "the bridge works" went
/// unquestioned for several iterations, so ignoring it is now a warning.
#[must_use]
pub fn publish_resolved_matches(matches: &[ResolvedMatch]) -> BridgeStats {
    publish_identifications(
        matches.iter().map(|m| (m.address, m.primary_name.as_str())),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustre_analysis_typerecov::{
        infer_function_signature, Confidence, _clear_function_signatures_for_test,
    };

    /// The registry is process-global, so these tests must not run concurrently
    /// with each other. They are serialised behind one mutex rather than split
    /// into separate `#[test]` fns that would race under the default harness.
    static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

    // ── type translation ────────────────────────────────────────────────────

    #[test]
    fn scalar_widths_and_signedness_survive_translation() {
        assert_eq!(to_recovered_type(&TypeDescriptor::U8), RecoveredType::Int { width: 1, signed: false });
        assert_eq!(to_recovered_type(&TypeDescriptor::I32), RecoveredType::Int { width: 4, signed: true });
        assert_eq!(to_recovered_type(&TypeDescriptor::U64), RecoveredType::Int { width: 8, signed: false });
        assert_eq!(to_recovered_type(&TypeDescriptor::F32), RecoveredType::Float { width: 4 });
        assert_eq!(to_recovered_type(&TypeDescriptor::F64), RecoveredType::Float { width: 8 });
    }

    #[test]
    fn pointer_nesting_is_preserved() {
        let td = TypeDescriptor::Pointer(Box::new(TypeDescriptor::Pointer(Box::new(
            TypeDescriptor::I8,
        ))));
        let rt = to_recovered_type(&td);
        // char ** — two levels, innermost a signed 1-byte int.
        match rt {
            RecoveredType::Pointer(inner) => match *inner {
                RecoveredType::Pointer(innermost) => {
                    assert_eq!(*innermost, RecoveredType::Int { width: 1, signed: true });
                }
                other => panic!("expected a second pointer level, got {other:?}"),
            },
            other => panic!("expected a pointer, got {other:?}"),
        }
    }

    #[test]
    fn inexpressible_types_degrade_to_unknown_not_to_a_near_miss() {
        // A union is not a struct: claiming it were would assert a layout we do
        // not have. `Unknown` is the honest answer.
        assert_eq!(to_recovered_type(&TypeDescriptor::Union("U".into())), RecoveredType::Unknown);
        assert_eq!(to_recovered_type(&TypeDescriptor::Enum("E".into())), RecoveredType::Unknown);
        assert_eq!(to_recovered_type(&TypeDescriptor::Void), RecoveredType::Unknown);
    }

    // ── arity fidelity through the bridge ───────────────────────────────────

    #[test]
    fn record_arity_matches_the_published_prototype() {
        let index = prototype_index();
        for (name, arity) in [("strdup", 1), ("strchr", 2), ("memcpy", 3), ("strlen", 1)] {
            let sig = index.get(name).unwrap_or_else(|| panic!("missing {name}"));
            let rec = to_signature_record(sig);
            assert_eq!(rec.args.len(), arity, "arity of `{name}` through the bridge");
        }
    }

    // ── end-to-end: a FLIRT name becomes a recovered signature ──────────────

    #[test]
    fn a_flirt_identification_becomes_a_high_confidence_signature() {
        let _g = SERIAL.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        _clear_function_signatures_for_test();

        // Before: type recovery knows nothing about this address.
        let before = infer_function_signature(0x1400_1000);
        assert_eq!(before.confidence, Confidence::Low, "expected no prior knowledge");

        let stats = publish_identifications([(0x1400_1000u64, "memcpy")]);
        assert_eq!(stats.considered, 1);
        assert_eq!(stats.published, 1);
        assert_eq!(stats.skipped_unknown_prototype, 0);

        // After: the prototype is there, with the right arity and convention.
        let after = infer_function_signature(0x1400_1000);
        assert_eq!(after.args.len(), 3, "memcpy takes three arguments");
        assert_eq!(after.calling_convention, "sysv_x64");
        assert_ne!(
            after.confidence,
            Confidence::Low,
            "a known prototype must raise confidence above the no-knowledge floor"
        );

        _clear_function_signatures_for_test();
    }

    #[test]
    fn an_unknown_name_publishes_nothing_rather_than_guessing() {
        let _g = SERIAL.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        _clear_function_signatures_for_test();

        let stats = publish_identifications([(0x2000u64, "some_app_specific_function")]);
        assert_eq!(stats.published, 0);
        assert_eq!(stats.skipped_unknown_prototype, 1);
        assert!((stats.publish_rate() - 0.0).abs() < f64::EPSILON);

        // Crucially: the registry must be untouched, not filled with a guess.
        assert_eq!(infer_function_signature(0x2000).confidence, Confidence::Low);

        _clear_function_signatures_for_test();
    }

    #[test]
    fn stats_count_every_match_and_rate_is_bounded() {
        let _g = SERIAL.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        _clear_function_signatures_for_test();

        let stats = publish_identifications([
            (0x10u64, "memcpy"),
            (0x20u64, "strlen"),
            (0x30u64, "not_a_libc_function"),
        ]);
        assert_eq!(stats.considered, 3);
        assert_eq!(stats.published, 2);
        assert_eq!(stats.skipped_unknown_prototype, 1);
        assert_eq!(
            stats.published + stats.skipped_unknown_prototype,
            stats.considered,
            "every considered match must be accounted for in exactly one bucket"
        );
        assert!(stats.publish_rate() > 0.66 && stats.publish_rate() < 0.67);

        _clear_function_signatures_for_test();
    }

    #[test]
    fn empty_input_is_a_zero_rate_not_a_division_by_zero() {
        let stats = publish_identifications(std::iter::empty::<(u64, &str)>());
        assert_eq!(stats, BridgeStats::default());
        assert!((stats.publish_rate() - 0.0).abs() < f64::EPSILON);
    }
}
