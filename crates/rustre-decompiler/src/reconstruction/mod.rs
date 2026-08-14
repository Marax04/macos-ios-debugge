//! Reconstruction layer: turning a decompiled binary into an *explained*
//! reconstruction rather than an unqualified listing.
//!
//! # Why this module exists
//!
//! The rest of the pipeline answers "what is the C for this function?". This
//! layer answers the two questions that make the output trustworthy:
//!
//!   1. **How much of this do we actually know?** Every recovered fact carries
//!      evidence and a confidence, so a caller can tell an arity backed by a
//!      published prototype from one guessed off a live register.
//!   2. **What is this binary made of?** Language, compiler, runtime and the
//!      project-level shape the functions imply.
//!
//! # The one design rule here: signals are ONE-DIRECTIONAL
//!
//! A signal may only ever LOWER confidence, never raise it. The pipeline
//! already follows this for LLIL coverage, and the reason generalises: a
//! function whose instructions all lifted cleanly is not thereby *more*
//! correct, it merely failed to trip one alarm. Absence of evidence is not
//! evidence of correctness. Any new signal added here must obey the same rule.
//!
//! # Honesty constraints for anything added to this module
//!
//! * A signal that cannot be measured must not be reported. There is no
//!   placeholder or "unknown = 100%" fallback; a missing signal is `None` and
//!   the report says so.
//! * Recovered *hypotheses* (project layout, file grouping) must be labelled
//!   as hypotheses. File boundaries largely do not survive optimisation, so
//!   this layer offers plausible clustering, never a claim to have recovered
//!   the original source tree.

pub mod confidence;
pub mod toolchain;
