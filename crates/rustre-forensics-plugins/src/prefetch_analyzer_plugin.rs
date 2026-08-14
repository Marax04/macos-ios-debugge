//! Re-export shim — the canonical Prefetch parser lives in
//! [`crate::plugins::prefetch_analyzer`].
//!
//! `prefetch_analyzer_plugin` was a near-duplicate of `plugins::prefetch_analyzer`.
//! All unique logic (the `PrefetchPlugin` batch wrapper) has been migrated into
//! the canonical module.  This shim re-exports everything so that any existing
//! code that references `prefetch_analyzer_plugin::*` continues to compile
//! without changes.

pub use crate::plugins::prefetch_analyzer::*;
