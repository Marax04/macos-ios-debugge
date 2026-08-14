//! Each recovery level must degrade safely (T26).
//!
//! # The property
//!
//! The recovery ladder is `size → primitive → pointer → struct → array → vtable
//! → signature`. Each rung stands on the one below. The property that makes the
//! whole thing trustworthy is not "every rung is right" — it is:
//!
//! > when the evidence underneath is ambiguous, a rung must report **less**, not
//! > guess **more**.
//!
//! This is the theme of every real defect found in this project. A phantom
//! parameter on `strdup`, a rust-stdlib name on a C function, a `bool` collapsed
//! into a struct layout it does not have — none of them fail loudly. They all
//! compile, look healthy, and corrupt whatever consumes them. An `Unknown` is
//! visibly useless; a wrong type is invisibly wrong.
//!
//! So these tests feed each level *deliberately insufficient or contradictory*
//! evidence and assert it admits the uncertainty.

use rustre_analysis_typerecov::struct_recovery_engine::{FieldAccess, StructRecoveryEngine};
use rustre_analysis_typerecov::{RecoveredType, TypeVar};

fn v(i: u32) -> TypeVar {
    TypeVar::new(i)
}

// ─── level: struct ───────────────────────────────────────────────────────────

#[test]
fn no_accesses_recovers_no_struct() {
    // Nothing observed must yield nothing — not an empty struct presented as a
    // finding. A zero-field struct in the output reads as "this is a struct with
    // no fields", which is a claim, not an absence of one.
    let engine = StructRecoveryEngine::default();
    assert!(engine.recover_for(v(1)).is_none(), "nessun accesso, nessuno struct");
    assert!(engine.recover_structs_all().is_empty());
}

#[test]
fn a_struct_is_only_recovered_for_a_base_that_was_actually_observed() {
    // Asking about an unobserved variable must not synthesise a layout from
    // another variable's accesses.
    let mut engine = StructRecoveryEngine::default();
    engine.record(FieldAccess::read(v(1), 0, 8, 0x1000));
    engine.record(FieldAccess::read(v(1), 8, 4, 0x1004));

    assert!(engine.recover_for(v(1)).is_some(), "la base osservata deve dare uno struct");
    assert!(
        engine.recover_for(v(99)).is_none(),
        "una base mai osservata non deve produrre un layout"
    );
}

#[test]
fn overlapping_accesses_are_reported_not_silently_merged() {
    // Two accesses covering the same bytes at different widths are genuinely
    // ambiguous: it could be a union, a bitfield, or two different structs
    // sharing a pointer. The engine must *flag* it rather than pick one.
    let mut engine = StructRecoveryEngine::default();
    engine.record(FieldAccess::read(v(1), 0, 8, 0x1000));
    engine.record(FieldAccess::read(v(1), 0, 4, 0x1004));
    engine.record(FieldAccess::write(v(1), 2, 2, 0x1008));

    let s = engine.recover_for(v(1)).expect("accessi osservati");
    assert!(
        s.has_overlaps,
        "accessi sovrapposti devono essere segnalati: scegliere in silenzio una \
         delle interpretazioni possibili è il difetto, non la soluzione"
    );
    assert!(
        !engine.find_conflicts(v(1)).is_empty(),
        "un conflitto osservabile deve essere elencabile"
    );
}

#[test]
fn a_gap_between_fields_is_marked_as_padding_not_filled_in() {
    // Bytes never touched are unknown, not zero and not part of a field.
    // Inventing a filler field would claim a layout the evidence does not show.
    let mut engine = StructRecoveryEngine::default();
    engine.record(FieldAccess::read(v(1), 0, 4, 0x1000));
    engine.record(FieldAccess::read(v(1), 64, 4, 0x1004));

    let s = engine.recover_for(v(1)).expect("accessi osservati");
    assert!(s.has_padding, "il buco fra +4 e +64 deve essere segnalato come padding");
    assert!(
        s.field_at(16).is_none(),
        "nessun campo deve essere inventato in un intervallo mai acceduto"
    );
    assert_eq!(s.fields.len(), 2, "solo i due campi osservati");
}

#[test]
fn recovered_size_never_exceeds_what_was_observed() {
    // `total_size` is an inference; it must be bounded by evidence. A size
    // larger than the furthest access would let a caller read past the object —
    // the `count_set_flags` failure mode already documented in this repo.
    let mut engine = StructRecoveryEngine::default();
    engine.record(FieldAccess::read(v(1), 0, 4, 0x1000));
    engine.record(FieldAccess::read(v(1), 8, 8, 0x1004));

    let s = engine.recover_for(v(1)).expect("accessi osservati");
    assert!(
        s.total_size <= 16,
        "total_size {} supera l'accesso più lontano (8+8=16)",
        s.total_size
    );
}

#[test]
fn a_union_candidate_requires_actual_overlap_not_just_offset_zero() {
    // Several fields at offset 0 alone is not evidence of a union; without
    // overlap it is just a struct whose first field was read at one width.
    let mut engine = StructRecoveryEngine::default();
    engine.record(FieldAccess::read(v(1), 0, 4, 0x1000));
    engine.record(FieldAccess::read(v(1), 4, 4, 0x1004));

    let s = engine.recover_for(v(1)).expect("accessi osservati");
    assert!(
        !s.is_union_candidate(),
        "campi disgiunti non devono essere proposti come union"
    );
}

// ─── level: pointer / primitive ──────────────────────────────────────────────

#[test]
fn unknown_is_not_a_pointer_and_has_no_pointee() {
    // The bottom of the lattice must not answer structural questions. If
    // `Unknown` claimed to be a pointer, every unresolved variable would grow a
    // dereference the evidence never showed.
    let u = RecoveredType::Unknown;
    assert!(!u.is_pointer());
    assert!(!u.is_struct());
    assert_eq!(u.pointee(), None);
}

#[test]
fn a_pointer_to_unknown_stays_a_pointer_to_unknown() {
    // Partial information must survive as partial. Collapsing `*Unknown` to
    // `Unknown` loses the one fact we had; promoting it to `*u8` invents one.
    let p = RecoveredType::Pointer(Box::new(RecoveredType::Unknown));
    assert!(p.is_pointer());
    assert_eq!(p.pointee(), Some(&RecoveredType::Unknown));
}

#[test]
fn display_names_never_claim_more_than_the_type_knows() {
    // The rendered name is what reaches emitted C. An `Unknown` printed as a
    // concrete type is a wrong answer with a straight face.
    let unknown = RecoveredType::Unknown.display_name();
    assert!(
        unknown.contains("unk") || unknown.contains("?") || unknown.contains("void"),
        "Unknown si presenta come {unknown:?}: deve restare visibilmente incerto"
    );

    let ptr_unknown = RecoveredType::Pointer(Box::new(RecoveredType::Unknown)).display_name();
    assert!(
        ptr_unknown.contains('*'),
        "un puntatore deve mostrarsi come tale, ottenuto {ptr_unknown:?}"
    );
}

// ─── ordering / determinism of the struct level ──────────────────────────────

#[test]
fn field_recovery_is_independent_of_access_order() {
    // Accesses arrive in disassembly order. Reordering them must not change the
    // recovered layout, or the struct depends on where the walk happened to
    // start.
    let accesses = [
        FieldAccess::read(v(1), 0, 8, 0x1000),
        FieldAccess::read(v(1), 8, 4, 0x1004),
        FieldAccess::write(v(1), 12, 4, 0x1008),
        FieldAccess::read(v(1), 16, 8, 0x100c),
    ];

    let layout = |order: Vec<usize>| -> Vec<(u32, u8)> {
        let mut e = StructRecoveryEngine::default();
        for i in order {
            e.record(accesses[i].clone());
        }
        e.recover_for(v(1))
            .map(|s| s.fields.iter().map(|f| (f.offset, f.size)).collect())
            .unwrap_or_default()
    };

    let forward = layout(vec![0, 1, 2, 3]);
    assert!(!forward.is_empty(), "il corpus deve produrre campi");
    assert_eq!(layout(vec![3, 2, 1, 0]), forward, "ordine inverso");
    assert_eq!(layout(vec![2, 0, 3, 1]), forward, "ordine mescolato");
}

#[test]
fn fields_come_back_sorted_by_offset() {
    // Documented invariant of `RecoveredStruct`. A consumer emitting C relies on
    // it: fields printed out of order produce a struct with a different layout
    // from the one recovered.
    let mut e = StructRecoveryEngine::default();
    for (off, size) in [(24u32, 4u8), (0, 8), (16, 8), (8, 4)] {
        e.record(FieldAccess::read(v(1), off, size, 0x1000));
    }
    let s = e.recover_for(v(1)).expect("accessi osservati");
    let offsets: Vec<u32> = s.fields.iter().map(|f| f.offset).collect();
    let mut sorted = offsets.clone();
    sorted.sort_unstable();
    assert_eq!(offsets, sorted, "i campi non sono ordinati per offset");
}
