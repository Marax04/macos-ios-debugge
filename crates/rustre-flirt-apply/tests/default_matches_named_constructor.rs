//! `Default` must never disagree with the type's own constructor.
//!
//! # The trap
//!
//! A `#[derive(Default)]` on a config struct sets every numeric field to `0`.
//! For a **threshold** that is not a neutral starting point — it is a degenerate
//! configuration that silently disables the check the field exists to enforce:
//!
//! * `min_confidence: 0.0` accepts every match, however weak;
//! * `min_pattern_len: 0` accepts a zero-byte pattern, which matches everywhere;
//! * `max_func_size: 0` is worse still — a *maximum* of zero rejects
//!   **everything**, so the extractor silently produces nothing.
//!
//! None of these fail loudly. They produce plausible, empty or over-full output.
//!
//! # What was found
//!
//! `StructRecoveryEngine` was caught first (iteration 34): derived `Default`
//! gave `pointer_width: 0` and `min_access_count: 0`, which made
//! `recover_for` return a zero-field struct for *every* variable and left
//! `looks_like_pointer` unable to ever fire. Scanning for siblings found **six
//! more**, every one with a sane named constructor and a zeroing `Default`:
//!
//! | type | field | `new()` | derived `Default` |
//! |---|---|---|---|
//! | `FlirtEngine` | `min_pattern_len` | 4 | 0 |
//! | `ObjFileParser` | `min_func_size` | 4 | 0 |
//! | `FunctionExtractor` | `max_func_size` | 65536 | **0** |
//! | `PrologueSampler` | `min_occurrences` | 2 | 0 |
//! | `SigOptimizer` | `min_exact_bytes` | 4 | 0 |
//! | `BatchApply` | `min_confidence` | 0.5 | 0.0 |
//!
//! All seven now delegate. These tests keep them delegating.

use rustre_analysis_typerecov::struct_recovery_engine::StructRecoveryEngine;
use rustre_flirt::flirt_engine::FlirtEngine;
use rustre_flirt_apply::recognition_session::BatchApply;
use rustre_flirt_gen::lib_analyzer::{FunctionExtractor, ObjFileParser, PrologueSampler};
use rustre_flirt_gen::sig_generator::SigOptimizer;

#[test]
fn flirt_engine_default_matches_new() {
    assert_eq!(
        FlirtEngine::default().min_pattern_len,
        FlirtEngine::new().min_pattern_len
    );
    assert!(
        FlirtEngine::default().min_pattern_len > 0,
        "min_pattern_len 0 accetterebbe un pattern di zero byte, che combacia ovunque"
    );
}

#[test]
fn obj_file_parser_default_matches_new() {
    assert_eq!(
        ObjFileParser::default().min_func_size,
        ObjFileParser::new().min_func_size
    );
    assert!(ObjFileParser::default().min_func_size > 0);
}

#[test]
fn function_extractor_default_is_not_a_zero_maximum() {
    // The nastiest of the seven: a *maximum* of zero rejects every function, so
    // the extractor produces nothing and reports no error.
    assert_eq!(
        FunctionExtractor::default().max_func_size,
        FunctionExtractor::new().max_func_size
    );
    assert!(
        FunctionExtractor::default().max_func_size > 0,
        "max_func_size 0 rifiuterebbe ogni funzione, in silenzio"
    );
}

#[test]
fn prologue_sampler_default_matches_new() {
    assert_eq!(
        PrologueSampler::default().min_occurrences,
        PrologueSampler::new().min_occurrences
    );
    assert!(PrologueSampler::default().min_occurrences > 0);
}

#[test]
fn sig_optimizer_default_matches_new() {
    assert_eq!(
        SigOptimizer::default().min_exact_bytes,
        SigOptimizer::new().min_exact_bytes
    );
    assert!(
        SigOptimizer::default().min_exact_bytes > 0,
        "min_exact_bytes 0 accetterebbe firme senza alcun byte esatto"
    );
}

#[test]
fn batch_apply_default_matches_new() {
    let d = BatchApply::default().min_confidence;
    assert!(
        (d - BatchApply::new().min_confidence).abs() < f64::EPSILON,
        "Default e new() divergono su min_confidence"
    );
    assert!(
        d > 0.0,
        "min_confidence 0 accetterebbe qualsiasi match, per quanto debole"
    );
}

#[test]
fn struct_recovery_engine_default_matches_new_64bit() {
    // The one that started the hunt.
    let d = StructRecoveryEngine::default();
    let n = StructRecoveryEngine::new_64bit();
    assert_eq!(d.pointer_width, n.pointer_width);
    assert_eq!(d.min_access_count, n.min_access_count);
    assert!(
        d.pointer_width > 0,
        "pointer_width 0 rende `looks_like_pointer` incapace di scattare"
    );
    assert!(
        d.min_access_count > 0,
        "min_access_count 0 fabbrica uno struct vuoto per ogni variabile"
    );
}
