//! Sub-crate registry / dispatcher for the `rustre-fuzz` hub.
//!
//! Every fuzzing backend sub-crate is wired here so that a hub consumer can
//! enumerate the available backends and obtain a representative entry-type
//! constructor for each.
//!
//! The registry is intentionally lightweight: each entry exposes the
//! sub-crate's name plus a short description of its primary exported type.
//! Concrete backends are constructed on demand by callers because their
//! constructors typically need a target/executor that the hub cannot
//! supply itself.

/// A single backend registered with the hub.
#[derive(Debug, Clone, Copy)]
pub struct BackendEntry {
    /// Crate name (matches `Cargo.toml` `[package].name`).
    pub crate_name: &'static str,
    /// Primary exported type from the sub-crate.
    pub primary_type: &'static str,
    /// One-line description of what this backend offers.
    pub description: &'static str,
}

/// AFL++-style coverage-guided backend
/// ([`rustre_fuzz_afl::AflFuzzer`]).
pub const AFL: BackendEntry = BackendEntry {
    crate_name: "rustre-fuzz-afl",
    primary_type: "AflFuzzer",
    description: "AFL++-style coverage-guided fuzzer with fork server and CMPLOG",
};

/// Coverage-tracking backend
/// ([`rustre_fuzz_cov::CoverageDatabase`]).
pub const COV: BackendEntry = BackendEntry {
    crate_name: "rustre-fuzz-cov",
    primary_type: "CoverageDatabase",
    description: "DRcov / lcov / SanCov coverage tracking and corpus pruning",
};

/// libFuzzer-style in-process backend
/// ([`rustre_fuzz_libfuzzer::InProcessFuzzer`]).
pub const LIBFUZZER: BackendEntry = BackendEntry {
    crate_name: "rustre-fuzz-libfuzzer",
    primary_type: "InProcessFuzzer",
    description: "libFuzzer-style in-process fuzzer with persistent harness",
};

/// Network / stateful protocol backend
/// ([`rustre_fuzz_net::ProtocolFuzzer`]).
pub const NET: BackendEntry = BackendEntry {
    crate_name: "rustre-fuzz-net",
    primary_type: "ProtocolFuzzer",
    description: "Boofuzz-style network/protocol state-machine fuzzer",
};

/// Sanitizer backend
/// ([`rustre_fuzz_sanitizers::AddressSanitizer`]).
pub const SANITIZERS: BackendEntry = BackendEntry {
    crate_name: "rustre-fuzz-sanitizers",
    primary_type: "AddressSanitizer",
    description: "Pure-Rust ASan / MSan / UBSan logic equivalents",
};

/// All sub-crates wired to this hub, in registration order.
#[must_use]
pub fn all() -> Vec<BackendEntry> {
    vec![AFL, COV, LIBFUZZER, NET, SANITIZERS]
}

/// Look up a backend by crate name.
#[must_use]
pub fn find(crate_name: &str) -> Option<BackendEntry> {
    all().into_iter().find(|b| b.crate_name == crate_name)
}

// Re-exports of each sub-crate's primary type so callers can construct
// backends through the hub without separately depending on every sub-crate.
// Gated behind the `backends` feature because the backend crates depend on
// this hub for shared primitives (Corpus, CoverageMap, FuzzInput,
// TargetExecutor, fnv1a, ...) — pulling them in unconditionally would form a
// build cycle. Enable the feature in the top-level binary / CLI crate.
// `rustre_fuzz_afl::AflFuzzer` is intentionally NOT re-exported here:
// `rustre-fuzz-afl` depends on this hub crate for shared primitives, so any
// dependency edge in the opposite direction (even optional) is rejected by
// cargo as a path-dependency cycle. Consumers should import the AFL backend
// directly via `use rustre_fuzz_afl::AflFuzzer;`.
#[cfg(feature = "backends")]
pub use rustre_fuzz_cov::CoverageDatabase;
// `rustre_fuzz_libfuzzer::InProcessFuzzer` and `rustre_fuzz_net::ProtocolFuzzer`
// are intentionally NOT re-exported here for the same reason as the AFL
// backend above: both crates transitively depend on this hub through
// `rustre-fuzz-afl`, so cargo rejects a reverse path edge. Consumers import
// those backends directly via `rustre_fuzz_libfuzzer::*` / `rustre_fuzz_net::*`.
#[cfg(feature = "backends")]
pub use rustre_fuzz_sanitizers::AddressSanitizer;
