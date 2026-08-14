//! `rustre-analysis-typerecov`
//!
//! Type recovery analysis for the `RustRE` platform.
//!
//! Provides a constraint-based type recovery pipeline:
//! 1. [`type_constraint_generator`] — walk the IL and emit type constraints.
//! 2. [`type_unifier`]             — unify constraints via union-find.
//! 3. [`struct_recovery_engine`]   — recover struct shapes from field accesses.

// These crates parse third-party `.sig`, `.pat` and `.lib` files. Every memory
// error in a parser of untrusted input is a security bug, so the whole family
// is kept free of `unsafe` by construction rather than by convention: the
// compiler refuses to build a violation.
//
// Measured 2026-07-29: all four crates already contained zero `unsafe` blocks.
// (An earlier inventory reported "3 unsafe in rustre-flirt-apply" — that was a
// grep counting the *word* inside comments that said "no unsafe".)
#![forbid(unsafe_code)]
pub mod attribute_bridge;
pub mod mem_access_scanner;
pub mod struct_recovery_engine;
pub mod type_constraint_generator;
pub mod type_unifier;

/// Shared test-only PRNG for the crate's randomized property tests.
///
/// One definition instead of the five per-test `fn xs` copies the test
/// modules used to carry. Identical algorithm, so no test's random sequence
/// changes.
#[cfg(test)]
pub(crate) mod test_prng {
    /// One xorshift64 step: mutates the state in place and returns it.
    pub(crate) fn xorshift(state: &mut u64) -> u64 {
        let mut x = *state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        *state = x;
        x
    }
}

pub use type_constraint_generator::{ConstraintKind, TypeConstraint, TypeConstraintGenerator};
pub use type_unifier::{UnificationResult, UnifyError, TypeUnifier};
pub use struct_recovery_engine::{FieldAccess, RecoveredStruct, StructRecoveryEngine};

// Re-export the legacy per-argument struct from rustre-analysis-type so callers
// can continue using it through this crate without an extra direct dependency.
// The signature-level API (`InferredSignature` + `infer_function_signature`) is
// redefined locally below to expose a richer, enum-based confidence value and a
// dedicated `ArgSpec` record (see §6.6 type-recovery integration notes).
pub use rustre_analysis_type::InferredArg;

// ─────────────────────────────────────────────────────────────────────────────
// Per-address signature inference  (addr-keyed)
//
// Uses the existing type-recovery helpers in `rustre-analysis-type`
// (`TypeEnvironment`, `TypeFact::display_name`, the WinAPI signature
// database, and `LibraryTypeImporter`) to recover a function's calling
// convention, return type, and argument types from its entry address.
//
// Confidence rules (per the type-recovery spec):
//   * `High`   — calling convention known **and** every argument has a
//                concrete (non-`Unknown`) type.
//   * `Medium` — only the calling convention is known.
//   * `Low`    — neither the calling convention nor any argument type is known.
// ─────────────────────────────────────────────────────────────────────────────

use serde::{Deserialize, Serialize};

/// One recovered argument: positional name and a human-readable type string.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ArgSpec {
    pub name: String,
    pub ty: String,
}

/// Confidence level attached to an [`InferredSignature`].
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum Confidence {
    Low,
    Medium,
    High,
}

/// Fully recovered signature for a function at a given virtual address.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct InferredSignature {
    pub calling_convention: String,
    pub return_type: String,
    pub args: Vec<ArgSpec>,
    pub confidence: Confidence,
}

/// Registry of per-address signature facts, populated by the binary loader
/// / lifter as it identifies functions.  This is read-mostly, so a plain
/// `Mutex<HashMap<…>>` is sufficient and avoids pulling in `parking_lot`
/// purely for this lookup path.
static SIGNATURE_REGISTRY: std::sync::Mutex<
    Option<std::collections::HashMap<u64, FunctionSignatureRecord>>,
> = std::sync::Mutex::new(None);

/// What the loader / lifter records for a single function address.
///
/// All fields are optional: a stripped binary may yield only a calling
/// convention, only a partial argument list, or nothing at all.  The
/// confidence-classification logic in [`infer_function_signature`] treats
/// `None` and `RecoveredType::Unknown` identically.
#[derive(Debug, Clone, Default)]
pub struct FunctionSignatureRecord {
    pub calling_convention: Option<String>,
    pub return_type: Option<RecoveredType>,
    pub args: Vec<(String, RecoveredType)>,
}

/// Register a recovered signature for the function at `addr`.
///
/// Intended to be called by the binary-loading / lifting layer once
/// per-function ABI detection has run.  Idempotent — subsequent calls
/// replace the prior record.
///
/// # Panics
///
/// Panics if the global signature registry mutex is poisoned.
pub fn register_function_signature(addr: u64, record: FunctionSignatureRecord) {
    let mut guard = SIGNATURE_REGISTRY.lock().expect("signature-registry poisoned");
    guard
        .get_or_insert_with(std::collections::HashMap::new)
        .insert(addr, record);
}

/// Clear all registered signatures.  Test-support helper.
#[doc(hidden)]
pub fn _clear_function_signatures_for_test() {
    let mut guard = SIGNATURE_REGISTRY.lock().expect("signature-registry poisoned");
    if let Some(m) = guard.as_mut() {
        m.clear();
    }
}

/// Infer the complete function signature for the function at `addr`.
///
/// Uses the per-address registry populated by the lifter; falls back to
/// an all-`Unknown` signature when nothing has been recorded for `addr`
/// (which yields `Confidence::Low`).
///
/// # Panics
///
/// Panics if the global signature registry mutex is poisoned.
#[must_use]
pub fn infer_function_signature(addr: u64) -> InferredSignature {
    let record = {
        let guard = SIGNATURE_REGISTRY.lock().expect("signature-registry poisoned");
        guard
            .as_ref()
            .and_then(|m| m.get(&addr).cloned())
            .unwrap_or_default()
    };

    let cc_known = record.calling_convention.is_some();
    let calling_convention = record
        .calling_convention
        .unwrap_or_else(|| "unknown".to_string());

    let return_type = record
        .return_type
        .as_ref().map_or_else(|| "?".to_string(), RecoveredType::display_name);

    let args: Vec<ArgSpec> = record
        .args
        .into_iter()
        .enumerate()
        .map(|(i, (name, ty))| ArgSpec {
            name: if name.is_empty() { format!("arg{i}") } else { name },
            ty: ty.display_name(),
        })
        .collect();

    let all_args_typed =
        args.iter().all(|a| a.ty != "?" && a.ty != RecoveredType::Unknown.display_name());

    let confidence = if cc_known && all_args_typed {
        Confidence::High
    } else if cc_known {
        Confidence::Medium
    } else {
        Confidence::Low
    };

    InferredSignature {
        calling_convention,
        return_type,
        args,
        confidence,
    }
}

#[cfg(test)]
mod signature_inference_tests {
    use super::*;

    /// Serialises tests that mutate the shared `SIGNATURE_REGISTRY`, since
    /// cargo runs unit tests in parallel by default.
    static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// CC known + every arg has a concrete type → High confidence.
    #[test]
    fn high_confidence_when_cc_and_all_args_typed() {
        let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        _clear_function_signatures_for_test();
        register_function_signature(
            0x1000,
            FunctionSignatureRecord {
                calling_convention: Some("microsoft-x64".to_string()),
                return_type: Some(RecoveredType::Int { width: 4, signed: true }),
                args: vec![
                    ("a".to_string(), RecoveredType::Int { width: 4, signed: true }),
                    ("b".to_string(), RecoveredType::Pointer(Box::new(
                        RecoveredType::Int { width: 1, signed: false },
                    ))),
                ],
            },
        );

        let sig = infer_function_signature(0x1000);
        assert_eq!(sig.calling_convention, "microsoft-x64");
        assert_eq!(sig.return_type, "i32");
        assert_eq!(sig.args.len(), 2);
        assert_eq!(sig.args[0], ArgSpec { name: "a".to_string(), ty: "i32".to_string() });
        assert_eq!(sig.args[1].ty, "*u8");
        assert_eq!(sig.confidence, Confidence::High);
    }

    /// CC known but at least one arg Unknown → Medium confidence.
    #[test]
    fn medium_confidence_when_only_cc_known() {
        let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        _clear_function_signatures_for_test();
        register_function_signature(
            0x2000,
            FunctionSignatureRecord {
                calling_convention: Some("sysv-amd64".to_string()),
                return_type: None,
                args: vec![
                    ("x".to_string(), RecoveredType::Int { width: 4, signed: true }),
                    ("y".to_string(), RecoveredType::Unknown),
                ],
            },
        );

        let sig = infer_function_signature(0x2000);
        assert_eq!(sig.calling_convention, "sysv-amd64");
        assert_eq!(sig.confidence, Confidence::Medium);
    }

    /// CC known + zero-argument (void) function → High confidence, since
    /// "every argument has a concrete type" is vacuously true for no args.
    #[test]
    fn high_confidence_for_zero_arg_function_with_known_cc() {
        let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        _clear_function_signatures_for_test();
        register_function_signature(
            0x3000,
            FunctionSignatureRecord {
                calling_convention: Some("microsoft-x64".to_string()),
                return_type: Some(RecoveredType::Int { width: 4, signed: true }),
                args: vec![],
            },
        );

        let sig = infer_function_signature(0x3000);
        assert_eq!(sig.calling_convention, "microsoft-x64");
        assert!(sig.args.is_empty());
        assert_eq!(sig.confidence, Confidence::High);
    }

    /// Nothing registered for `addr` → Low confidence.
    #[test]
    fn low_confidence_when_nothing_known() {
        let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        _clear_function_signatures_for_test();
        let sig = infer_function_signature(0xdead_beef);
        assert_eq!(sig.calling_convention, "unknown");
        assert!(sig.args.is_empty());
        assert_eq!(sig.confidence, Confidence::Low);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Shared type model
// ─────────────────────────────────────────────────────────────────────────────

/// A type variable (skolem) used during constraint generation and unification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
pub struct TypeVar(pub u32);

impl TypeVar {
    #[must_use]
    pub const fn new(v: u32) -> Self {
        Self(v)
    }
}

impl std::fmt::Display for TypeVar {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "τ{}", self.0)
    }
}

/// A concrete or partial type inferred during recovery.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[derive(Default)]
pub enum RecoveredType {
    /// Unresolved type variable.
    Var(TypeVar),
    /// Integer of the given byte-width.
    Int { width: u8, signed: bool },
    /// Floating point (32 or 64 bit).
    Float { width: u8 },
    /// Pointer to another type.
    Pointer(Box<Self>),
    /// Array of `count` elements of element type.
    Array { element: Box<Self>, count: usize },
    /// A recovered struct type with a known name.
    Struct { name: String },
    /// Function pointer.
    FnPtr { param_count: usize },
    /// The type could not be recovered.
    #[default]
    Unknown,
}

impl RecoveredType {
    /// Return `true` if this is a pointer type.
    #[must_use]
    pub const fn is_pointer(&self) -> bool {
        matches!(self, Self::Pointer(_))
    }

    /// Return `true` if this is a struct type.
    #[must_use]
    pub const fn is_struct(&self) -> bool {
        matches!(self, Self::Struct { .. })
    }

    /// Return the pointee type, if this is a pointer.
    #[must_use]
    pub fn pointee(&self) -> Option<&Self> {
        if let Self::Pointer(inner) = self {
            Some(inner)
        } else {
            None
        }
    }

    /// Human-readable description.
    #[must_use]
    pub fn display_name(&self) -> String {
        match self {
            Self::Var(v) => v.to_string(),
            // Widen to u32 BEFORE multiplying: `width` is a `u8`, so `width * 8`
            // overflows for anything past 31 bytes — a 32-byte type printed as
            // `u0` in release and panicked in an overflow-checked build. SIMD
            // vectors and large structs pass 31 bytes routinely.
            Self::Int { width, signed } => {
                let prefix = if *signed { "i" } else { "u" };
                format!("{prefix}{}", u32::from(*width) * 8)
            }
            Self::Float { width } => format!("f{}", u32::from(*width) * 8),
            Self::Pointer(inner) => format!("*{}", inner.display_name()),
            Self::Array { element, count } => format!("[{}; {count}]", element.display_name()),
            Self::Struct { name } => name.clone(),
            Self::FnPtr { param_count } => format!("fn({param_count})"),
            Self::Unknown => "?".to_string(),
        }
    }
}


/// Errors produced by the type-recovery pipeline.
#[derive(Debug, thiserror::Error)]
pub enum TypeRecovError {
    #[error("unification failed: {0}")]
    Unification(#[from] UnifyError),
    #[error("constraint generation error: {0}")]
    ConstraintGen(String),
    #[error("struct recovery error: {0}")]
    StructRecov(String),
}
