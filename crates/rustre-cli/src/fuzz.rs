//! Fuzz family hub-and-spokes registry (gated subset).
//!
//! Only the fuzz sub-crates that are currently part of the workspace
//! build are wired here. Sub-crates not present in the workspace
//! Cargo.toml are intentionally absent so the registry compiles.

pub use rustre_fuzz_cov as cov;
pub use rustre_fuzz_sanitizers as sanitizers;

use rustre_fuzz_cov::CoverageDatabase;
use rustre_fuzz_sanitizers::SanitizerHarness;

/// Identifies a fuzzing backend wired into the CLI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BackendKind {
    /// Coverage tracking and analysis (`rustre-fuzz-cov`).
    Coverage,
    /// Sanitizer-driven fuzzing (`rustre-fuzz-sanitizers`).
    Sanitizers,
}

impl BackendKind {
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Coverage => "coverage",
            Self::Sanitizers => "sanitizers",
        }
    }

    #[must_use]
    pub const fn all() -> &'static [Self] {
        &[Self::Coverage, Self::Sanitizers]
    }
}

pub trait FuzzerBackend: Send {
    fn kind(&self) -> BackendKind;
    fn name(&self) -> &'static str {
        self.kind().name()
    }
}

pub struct CovBackend {
    pub database: CoverageDatabase,
}

impl CovBackend {
    #[must_use]
    pub fn new() -> Self {
        Self { database: CoverageDatabase::new() }
    }
}

impl Default for CovBackend {
    fn default() -> Self { Self::new() }
}

impl FuzzerBackend for CovBackend {
    fn kind(&self) -> BackendKind { BackendKind::Coverage }
}

pub struct SanitizersBackend {
    pub harness: SanitizerHarness,
}

impl SanitizersBackend {
    #[must_use]
    pub fn new() -> Self {
        Self { harness: SanitizerHarness::new() }
    }
}

impl Default for SanitizersBackend {
    fn default() -> Self { Self::new() }
}

impl FuzzerBackend for SanitizersBackend {
    fn kind(&self) -> BackendKind { BackendKind::Sanitizers }
}

#[must_use]
pub fn make_backend(kind: BackendKind) -> Box<dyn FuzzerBackend> {
    match kind {
        BackendKind::Coverage => Box::new(CovBackend::new()),
        BackendKind::Sanitizers => Box::new(SanitizersBackend::new()),
    }
}
