//! Reaching the field-access cap must be an error, not a process kill (T24).
//!
//! # The third instance of one shape
//!
//! `StructRecoveryEngine::record_all` carried this, verbatim:
//!
//! ```text
//! /// Panics if the total number of recorded accesses would exceed
//! /// `MAX_ACCESSES` (8 M), preventing denial-of-service via memory
//! /// exhaustion when analysing adversarially-crafted binaries.
//! ```
//!
//! The doc names the threat and then answers it by panicking — the same shape
//! already found twice in the unifier. Field accesses come from the analysed
//! file, so their number is attacker-influenced.
//!
//! `try_record` and `try_record_all` now return
//! [`StructRecoveryError::TooManyAccesses`]; `record`/`record_all` remain and say
//! they panic.
//!
//! # A second defect the rewrite removed
//!
//! `record_all` asserted **inside** its loop, after having already pushed part
//! of the input. A caller that caught the panic was left with a half-filled
//! engine and no way to learn how much had gone in. `try_record_all` returns the
//! count it recorded, so a truncated run is distinguishable from a complete one.
//!
//! # Why the cap itself is not exercised here
//!
//! Reaching 8 M entries takes about a gigabyte of `FieldAccess`. A test that
//! allocated it would be slow and would measure the allocator, so these use a
//! small engine built through the same code path, plus assertions on the
//! constant and on the error value. What is verified is the *shape* of the
//! failure, which is what changed.

use rustre_analysis_typerecov::TypeVar;
use rustre_analysis_typerecov::struct_recovery_engine::{
    FieldAccess, StructRecoveryEngine, StructRecoveryError,
};

fn access(off: u32) -> FieldAccess {
    FieldAccess::read(TypeVar::new(1), off, 4, 0x1000 + u64::from(off))
}

#[test]
fn the_cap_is_public_and_documented() {
    assert_eq!(
        StructRecoveryEngine::MAX_ACCESSES,
        8 * 1024 * 1024,
        "il tetto e' cambiato: aggiorna il doc e rimisura il costo di memoria"
    );
}

#[test]
fn ordinary_recording_succeeds_through_the_fallible_path() {
    let mut e = StructRecoveryEngine::default();
    for i in 0..64u32 {
        e.try_record(access(i * 4))
            .expect("un accesso normale deve essere registrato");
    }
    let s = e.recover_for(TypeVar::new(1)).expect("accessi osservati");
    assert!(!s.fields.is_empty(), "nessun campo recuperato");
}

#[test]
fn try_record_all_reports_how_many_it_took() {
    let mut e = StructRecoveryEngine::default();
    let n = e
        .try_record_all((0..32u32).map(|i| access(i * 4)))
        .expect("nessun tetto raggiunto con 32 accessi");
    assert_eq!(
        n, 32,
        "il conteggio restituito distingue una corsa completa da una troncata"
    );
}

/// The error must carry the limit, so a caller can report it rather than
/// guessing why the analysis stopped.
#[test]
fn the_error_names_the_limit() {
    let err = StructRecoveryError::TooManyAccesses {
        limit: StructRecoveryEngine::MAX_ACCESSES,
    };
    let text = err.to_string();
    assert!(
        text.contains(&StructRecoveryEngine::MAX_ACCESSES.to_string()),
        "il messaggio non nomina il limite: {text}"
    );
}
