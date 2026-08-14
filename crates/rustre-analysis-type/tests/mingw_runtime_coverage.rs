//! Level 7 coverage: does the database the decompiler actually reads know the
//! runtime functions the corpus is full of?
//!
//! `LibrarySignatureDb` is the seam behind
//! `infer_function_signature_named(addr, name, cc, env, &lib_db)`, where a
//! published prototype wins over inference. Before the mingw-w64 runtime was
//! added it covered **3** of the corpus's 136 ground-truth names — libc, POSIX
//! and Win32, none of which is what a mingw-built binary is mostly made of.
//!
//! A published prototype *overrides* inference, so a wrong entry here does not
//! merely fail to help: it replaces a correct inference with a wrong answer.
//! That is why the entries are generated from headers rather than remembered.

use rustre_analysis_type::interprocedural::LibrarySignatureDb;

/// Names taken from `unwind.h`, with the arity the header declares.
const UNWIND: &[(&str, usize)] = &[
    ("_Unwind_GetIP", 1),
    ("_Unwind_SetIP", 2),
    ("_Unwind_GetCFA", 1),
    ("_Unwind_GetGR", 2),
    ("_Unwind_SetGR", 3),
    ("_Unwind_GetRegionStart", 1),
    ("_Unwind_GetLanguageSpecificData", 1),
    ("_Unwind_FindEnclosingFunction", 1),
    ("_Unwind_DeleteException", 1),
    ("_Unwind_RaiseException", 1),
];

#[test]
fn unwind_runtime_is_known_with_published_arity() {
    let db = LibrarySignatureDb::new();
    for (name, arity) in UNWIND {
        assert!(db.contains(name), "`{name}` manca da LibrarySignatureDb");
        let sig = db.lookup(name).unwrap_or_else(|| panic!("lookup fallito per `{name}`"));
        assert_eq!(sig.param_types.len(), *arity, "arità di `{name}`");
    }
}

/// `_Unwind_FindEnclosingFunction` is the case the project already knew was
/// uniformly wrong: emitted with 0 parameters in every build against a
/// published prototype of 1. Consistent across builds, and consistently wrong —
/// so cross-build consistency could never have caught it. Only a published
/// prototype can.
#[test]
fn the_uniformly_wrong_case_now_has_a_published_answer() {
    let db = LibrarySignatureDb::new();
    let sig = db
        .lookup("_Unwind_FindEnclosingFunction")
        .expect("il caso noto deve avere un prototipo pubblicato");
    assert_eq!(sig.param_types.len(), 1);
}

#[test]
fn pthread_family_is_covered_not_just_three_entries() {
    let db = LibrarySignatureDb::new();
    // The corpus ground truth is ~110 pthread names; before this change the db
    // knew exactly three of them.
    let probes = [
        "pthread_create_wrapper", "pthread_detach", "pthread_equal",
        "pthread_getspecific", "pthread_setspecific", "pthread_key_delete",
        "pthread_cond_wait", "pthread_cond_signal", "pthread_rwlock_rdlock",
        "pthread_spin_lock", "pthread_attr_init", "sched_yield",
    ];
    let missing: Vec<&str> = probes.iter().copied().filter(|n| !db.contains(n)).collect();
    assert!(missing.is_empty(), "non coperti: {missing:?}");
}

#[test]
fn hand_curated_entries_are_not_clobbered_by_the_generated_ones() {
    // `populate_mingw_runtime` runs last, so a name present in both sets keeps
    // whichever the ordering intends. `memcpy` is hand-curated as (void*, void*,
    // size_t) and must stay 3-ary regardless of what any header sweep produced.
    let db = LibrarySignatureDb::new();
    let sig = db.lookup("memcpy").expect("memcpy deve esserci");
    assert_eq!(sig.param_types.len(), 3, "memcpy resta a 3 parametri");
}

#[test]
fn no_signature_claims_a_parameter_count_of_zero_for_a_known_unary_function() {
    // Guard against the extractor mis-reading `(void)` vs `(T x)`: a function
    // wrongly recorded as 0-ary would *remove* a real parameter downstream,
    // which is the phantom-parameter defect in reverse and just as damaging.
    let db = LibrarySignatureDb::new();
    for (name, arity) in UNWIND {
        if *arity > 0 {
            let sig = db.lookup(name).unwrap();
            assert!(
                !sig.param_types.is_empty(),
                "`{name}` registrata come 0-aria ma la sua prototipo ne dichiara {arity}"
            );
        }
    }
}
