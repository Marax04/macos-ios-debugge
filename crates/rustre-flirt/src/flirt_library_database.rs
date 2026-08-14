//! `FlirtLibraryDatabase` — library-level FLIRT signature database.
//!
//! Organises FLIRT patterns into named library entries keyed by
//! (name, version, architecture, OS).  Provides a structured search
//! interface that returns ranked `LibraryMatch` results together with
//! a summary `LibraryReport`.

use std::collections::HashMap;
use std::str::FromStr;
// AHashMap prevents hash-collision DoS when keys are attacker-controlled strings
// from parsed .pat / .sig files (library names, arch strings, symbol names).
use ahash::AHashMap;

use crate::{FlirtError, FlirtPattern};

// ── Architecture ─────────────────────────────────────────────────────────────

/// Target CPU architecture for a library entry.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum LibraryArch {
    X86,
    X86_64,
    Arm,
    Arm64,
    Mips,
    Mips64,
    Ppc,
    Ppc64,
    Riscv32,
    Riscv64,
    Unknown(String),
}

impl FromStr for LibraryArch {
    type Err = std::convert::Infallible;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s.to_lowercase().as_str() {
            "x86" | "i386" | "i686" => Self::X86,
            "x86_64" | "x64" | "amd64" => Self::X86_64,
            "arm" | "armv7" | "thumb" => Self::Arm,
            "arm64" | "aarch64" => Self::Arm64,
            "mips" | "mipsel" => Self::Mips,
            "mips64" | "mips64el" => Self::Mips64,
            "ppc" | "powerpc" => Self::Ppc,
            "ppc64" | "powerpc64" => Self::Ppc64,
            "riscv32" => Self::Riscv32,
            "riscv64" => Self::Riscv64,
            other => Self::Unknown(other.to_string()),
        })
    }
}

impl LibraryArch {
    /// Parse from a canonical string such as `"x86_64"` or `"arm64"`.
    #[must_use]
    pub fn parse(s: &str) -> Self {
        s.parse().unwrap_or_else(|_| Self::Unknown(s.to_string()))
    }

    /// Canonical lowercase name.
    #[must_use]
    pub const fn canonical(&self) -> &str {
        match self {
            Self::X86 => "x86",
            Self::X86_64 => "x86_64",
            Self::Arm => "arm",
            Self::Arm64 => "arm64",
            Self::Mips => "mips",
            Self::Mips64 => "mips64",
            Self::Ppc => "ppc",
            Self::Ppc64 => "ppc64",
            Self::Riscv32 => "riscv32",
            Self::Riscv64 => "riscv64",
            Self::Unknown(s) => s.as_str(),
        }
    }
}

// ── OS ────────────────────────────────────────────────────────────────────────

/// Operating system for a library entry.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum LibraryOs {
    Linux,
    Windows,
    Macos,
    FreeBsd,
    Android,
    Ios,
    Bare,
    Unknown(String),
}

impl FromStr for LibraryOs {
    type Err = std::convert::Infallible;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s.to_lowercase().as_str() {
            "linux" => Self::Linux,
            "windows" | "win32" | "win64" => Self::Windows,
            "macos" | "darwin" | "osx" => Self::Macos,
            "freebsd" => Self::FreeBsd,
            "android" => Self::Android,
            "ios" => Self::Ios,
            "bare" | "none" | "freestanding" => Self::Bare,
            other => Self::Unknown(other.to_string()),
        })
    }
}

impl LibraryOs {
    /// Parse from a canonical string such as `"linux"` or `"windows"`.
    #[must_use]
    pub fn parse(s: &str) -> Self {
        s.parse().unwrap_or_else(|_| Self::Unknown(s.to_string()))
    }

    /// Canonical lowercase name.
    #[must_use]
    pub const fn canonical(&self) -> &str {
        match self {
            Self::Linux => "linux",
            Self::Windows => "windows",
            Self::Macos => "macos",
            Self::FreeBsd => "freebsd",
            Self::Android => "android",
            Self::Ios => "ios",
            Self::Bare => "bare",
            Self::Unknown(s) => s.as_str(),
        }
    }
}

// ── LibraryEntry ──────────────────────────────────────────────────────────────

/// Metadata for a single versioned library.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LibraryEntry {
    /// Human-readable name (e.g. `"libc"`, `"openssl"`).
    pub name: String,
    /// Version string (e.g. `"2.31"`, `"1.1.1k"`).
    pub version: String,
    /// Target architecture.
    pub arch: LibraryArch,
    /// Target operating system.
    pub os: LibraryOs,
    /// Optional compiler/toolchain tag (e.g. `"gcc-9"`, `"msvc-2019"`).
    pub compiler: Option<String>,
    /// Optional build variant (e.g. `"debug"`, `"release"`, `"stripped"`).
    pub variant: Option<String>,
}

impl LibraryEntry {
    /// Construct a new `LibraryEntry`.
    pub fn new(
        name: impl Into<String>,
        version: impl Into<String>,
        arch: LibraryArch,
        os: LibraryOs,
    ) -> Self {
        Self {
            name: name.into(),
            version: version.into(),
            arch,
            os,
            compiler: None,
            variant: None,
        }
    }

    /// Builder: set the compiler tag.
    #[must_use]
    pub fn with_compiler(mut self, compiler: impl Into<String>) -> Self {
        self.compiler = Some(compiler.into());
        self
    }

    /// Builder: set the variant tag.
    #[must_use]
    pub fn with_variant(mut self, variant: impl Into<String>) -> Self {
        self.variant = Some(variant.into());
        self
    }

    /// Returns a display string in the form `"name-version (arch/os)"`.
    #[must_use] 
    pub fn display_name(&self) -> String {
        format!(
            "{}-{} ({}/{})",
            self.name,
            self.version,
            self.arch.canonical(),
            self.os.canonical()
        )
    }
}

// ── LibrarySig ────────────────────────────────────────────────────────────────

/// A single FLIRT signature belonging to a library entry.
#[derive(Debug, Clone)]
pub struct LibrarySig {
    /// The underlying FLIRT pattern.
    pub pattern: FlirtPattern,
    /// Internal signature identifier (unique within a database).
    pub sig_id: u64,
    /// The library this signature belongs to.
    pub library_id: u64,
    /// Source `.pat` / `.sig` file from which this was loaded (informational).
    pub source_file: Option<String>,
    /// Confidence weight in [0.0, 1.0] assigned at import time.
    pub weight: f32,
}

impl LibrarySig {
    /// Create a new library signature.
    #[must_use] 
    pub const fn new(sig_id: u64, library_id: u64, pattern: FlirtPattern) -> Self {
        Self {
            pattern,
            sig_id,
            library_id,
            source_file: None,
            weight: 1.0,
        }
    }

    /// Builder: attach the source file name.
    #[must_use]
    pub fn with_source(mut self, source: impl Into<String>) -> Self {
        self.source_file = Some(source.into());
        self
    }

    /// Builder: set the confidence weight.
    #[must_use] 
    pub const fn with_weight(mut self, w: f32) -> Self {
        // NaN-safe clamp: `f32::clamp` propagates NaN and `is_nan()` is not
        // available in a const fn. A NaN weight would poison every score it
        // multiplies, so fall through to the documented lower bound.
        self.weight = if w >= 1.0 {
            1.0
        } else if w > 0.0 {
            w
        } else {
            0.0
        };
        self
    }
}

// ── LibrarySearch ─────────────────────────────────────────────────────────────

/// Search parameters used when querying the `FlirtLibraryDatabase`.
#[derive(Debug, Clone, Default)]
pub struct LibrarySearch {
    /// If `Some`, restrict matches to this library name (exact, case-insensitive).
    pub library_name: Option<String>,
    /// If `Some`, restrict matches to this architecture.
    pub arch: Option<LibraryArch>,
    /// If `Some`, restrict matches to this operating system.
    pub os: Option<LibraryOs>,
    /// Minimum confidence score to include in results.
    pub min_confidence: f32,
    /// Maximum number of results to return (default: all).
    pub max_results: Option<usize>,
    /// If `true`, only return the single best match per input byte slice.
    pub best_only: bool,
}

impl LibrarySearch {
    /// New search with no filters.
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    /// Filter by library name.
    #[must_use]
    pub fn with_library(mut self, name: impl Into<String>) -> Self {
        self.library_name = Some(name.into().to_lowercase());
        self
    }

    /// Filter by architecture.
    #[must_use] 
    pub fn with_arch(mut self, arch: LibraryArch) -> Self {
        self.arch = Some(arch);
        self
    }

    /// Filter by OS.
    #[must_use] 
    pub fn with_os(mut self, os: LibraryOs) -> Self {
        self.os = Some(os);
        self
    }

    /// Set minimum confidence.
    #[must_use] 
    pub const fn with_min_confidence(mut self, c: f32) -> Self {
        // NaN-safe clamp — see `with_weight`. A NaN threshold would reject every
        // signature match in silence.
        self.min_confidence = if c >= 1.0 {
            1.0
        } else if c > 0.0 {
            c
        } else {
            0.0
        };
        self
    }

    /// Limit number of results.
    #[must_use] 
    pub const fn with_max_results(mut self, n: usize) -> Self {
        self.max_results = Some(n);
        self
    }

    /// Only return the best match.
    #[must_use] 
    pub const fn best_only(mut self) -> Self {
        self.best_only = true;
        self
    }
}

// ── ConfidenceScore ───────────────────────────────────────────────────────────

/// Composite confidence score for a match.
#[derive(Debug, Clone, PartialEq)]
pub struct ConfidenceScore {
    /// Raw pattern-match score (initial bytes, crc16, tail bytes).
    pub pattern_score: f32,
    /// Signature weight from import time.
    pub sig_weight: f32,
    /// Combined score in [0.0, 1.0].
    pub combined: f32,
}

impl ConfidenceScore {
    /// Compute from components.
    #[must_use] 
    pub fn compute(pattern_score: f32, sig_weight: f32) -> Self {
        let combined = (pattern_score * sig_weight).clamp(0.0, 1.0);
        Self {
            pattern_score,
            sig_weight,
            combined,
        }
    }

    /// Returns `true` if combined score meets the given threshold.
    #[must_use] 
    pub fn meets(&self, threshold: f32) -> bool {
        self.combined >= threshold
    }
}

// ── LibraryMatch ──────────────────────────────────────────────────────────────

/// A single match result from the library database.
#[derive(Debug, Clone)]
pub struct LibraryMatch {
    /// The matching library entry.
    pub library: LibraryEntry,
    /// The matching signature.
    pub sig: LibrarySig,
    /// Primary function name resolved by this match.
    pub function_name: String,
    /// Confidence score.
    pub confidence: ConfidenceScore,
    /// Byte offset into the searched buffer at which the match starts.
    pub offset: usize,
}

impl LibraryMatch {
    /// Returns `true` if the match confidence meets `threshold`.
    #[must_use] 
    pub fn is_confident(&self, threshold: f32) -> bool {
        self.confidence.meets(threshold)
    }
}

// ── LibraryReport ─────────────────────────────────────────────────────────────

/// Summary report produced by a library search.
#[derive(Debug, Clone, Default)]
pub struct LibraryReport {
    /// Total signatures tested against the input buffer.
    pub sigs_tested: usize,
    /// Number of initial-pattern matches (before CRC/tail filtering).
    pub initial_matches: usize,
    /// Number of final confirmed matches.
    pub confirmed_matches: usize,
    /// All confirmed matches ordered by descending confidence.
    pub matches: Vec<LibraryMatch>,
    /// Names of libraries that contributed at least one match.
    pub matched_libraries: Vec<String>,
    /// Any warnings generated during the search.
    pub warnings: Vec<String>,
}

impl LibraryReport {
    /// Returns the best (highest-confidence) match, if any.
    #[must_use] 
    pub fn best_match(&self) -> Option<&LibraryMatch> {
        self.matches.first()
    }

    /// Returns only matches whose combined confidence is >= `threshold`.
    pub fn confident_matches(&self, threshold: f32) -> impl Iterator<Item = &LibraryMatch> {
        self.matches.iter().filter(move |m| m.is_confident(threshold))
    }

    /// Returns `true` when at least one match was found.
    #[must_use] 
    pub const fn has_matches(&self) -> bool {
        !self.matches.is_empty()
    }

    /// Flatten to a list of `(function_name, library_display_name, confidence)` tuples.
    #[must_use] 
    pub fn summary_tuples(&self) -> Vec<(String, String, f32)> {
        self.matches
            .iter()
            .map(|m| {
                (
                    m.function_name.clone(),
                    m.library.display_name(),
                    m.confidence.combined,
                )
            })
            .collect()
    }
}

// ── FlirtLibraryDatabase ─────────────────────────────────────────────────────

/// Central library database for FLIRT pattern matching.
///
/// Stores library entries and their associated signatures; supports indexed
/// lookup for fast pattern matching against byte slices.
pub struct FlirtLibraryDatabase {
    /// Next library ID to assign.
    next_lib_id: u64,
    /// Next signature ID to assign.
    next_sig_id: u64,
    /// Registered libraries, keyed by library ID.
    libraries: HashMap<u64, LibraryEntry>,
    /// All signatures, keyed by signature ID.
    sigs: HashMap<u64, LibrarySig>,
    /// Index: `library_name_lowercase` → [`lib_id`, …]
    /// `AHashMap`: keys are attacker-controlled library names.
    name_index: AHashMap<String, Vec<u64>>,
    /// Index: arch → [`sig_id`, …]
    /// `AHashMap`: keys are attacker-controlled arch strings.
    arch_index: AHashMap<String, Vec<u64>>,
    /// Index: first byte (or 0xFF for wildcard) → [`sig_id`, …]
    byte_index: HashMap<u8, Vec<u64>>,
}

impl FlirtLibraryDatabase {
    /// Create an empty database.
    #[must_use] 
    pub fn new() -> Self {
        Self {
            next_lib_id: 1,
            next_sig_id: 1,
            libraries: HashMap::new(),
            sigs: HashMap::new(),
            name_index: AHashMap::new(),
            arch_index: AHashMap::new(),
            byte_index: HashMap::new(),
        }
    }

    // ── Library management ────────────────────────────────────────────────

    /// Register a library entry and return its assigned ID.
    pub fn add_library(&mut self, entry: LibraryEntry) -> u64 {
        let id = self.next_lib_id;
        self.next_lib_id += 1;

        let key = entry.name.to_lowercase();
        self.name_index.entry(key).or_default().push(id);
        self.libraries.insert(id, entry);
        id
    }

    /// Retrieve a library by ID.
    #[must_use] 
    pub fn get_library(&self, id: u64) -> Option<&LibraryEntry> {
        self.libraries.get(&id)
    }

    /// Number of registered libraries.
    #[must_use] 
    pub fn library_count(&self) -> usize {
        self.libraries.len()
    }

    /// Iterator over all registered libraries.
    pub fn iter_libraries(&self) -> impl Iterator<Item = (u64, &LibraryEntry)> {
        self.libraries.iter().map(|(&id, e)| (id, e))
    }

    /// Remove a library and all its signatures from the database.
    pub fn remove_library(&mut self, lib_id: u64) -> Option<LibraryEntry> {
        let entry = self.libraries.remove(&lib_id)?;

        // remove from name index
        let key = entry.name.to_lowercase();
        if let Some(ids) = self.name_index.get_mut(&key) {
            ids.retain(|&x| x != lib_id);
        }

        // remove all signatures belonging to this library
        let sig_ids: Vec<u64> = self
            .sigs
            .values()
            .filter(|s| s.library_id == lib_id)
            .map(|s| s.sig_id)
            .collect();
        for sig_id in sig_ids {
            self.remove_sig(sig_id);
        }
        Some(entry)
    }

    // ── Signature management ──────────────────────────────────────────────

    /// Add a signature for an existing library.  Returns an error if the
    /// library ID is not registered.
    ///
    /// # Errors
    /// Returns `FlirtError::Database` if `library_id` is not registered.
    pub fn add_sig(
        &mut self,
        library_id: u64,
        pattern: FlirtPattern,
    ) -> Result<u64, FlirtError> {
        if !self.libraries.contains_key(&library_id) {
            return Err(FlirtError::Database(format!(
                "library {library_id} not found"
            )));
        }

        let sig_id = self.next_sig_id;
        self.next_sig_id += 1;

        // byte index on first initial byte
        let first_key = pattern
            .initial_bytes
            .first()
            .map_or(0xFF, |pb| match pb {
                crate::PatternByte::Exact(b) => *b,
                crate::PatternByte::Wildcard => 0xFF,
            });

        self.byte_index.entry(first_key).or_default().push(sig_id);

        // arch index
        let arch_key = self
            .libraries
            .get(&library_id)
            .map(|e| e.arch.canonical().to_string())
            .unwrap_or_default();
        self.arch_index
            .entry(arch_key)
            .or_default()
            .push(sig_id);

        let sig = LibrarySig::new(sig_id, library_id, pattern);
        self.sigs.insert(sig_id, sig);
        Ok(sig_id)
    }

    /// Add a signature with full configuration.
    ///
    /// # Errors
    /// Returns `FlirtError::Database` if the signature's library ID is not registered.
    pub fn add_sig_full(&mut self, sig: LibrarySig) -> Result<(), FlirtError> {
        let library_id = sig.library_id;
        if !self.libraries.contains_key(&library_id) {
            return Err(FlirtError::Database(format!(
                "library {library_id} not found"
            )));
        }

        let first_key = sig
            .pattern
            .initial_bytes
            .first()
            .map_or(0xFF, |pb| match pb {
                crate::PatternByte::Exact(b) => *b,
                crate::PatternByte::Wildcard => 0xFF,
            });

        self.byte_index.entry(first_key).or_default().push(sig.sig_id);

        let arch_key = self
            .libraries
            .get(&library_id)
            .map(|e| e.arch.canonical().to_string())
            .unwrap_or_default();
        self.arch_index
            .entry(arch_key)
            .or_default()
            .push(sig.sig_id);

        self.sigs.insert(sig.sig_id, sig);
        Ok(())
    }

    /// Remove a signature by ID.
    pub fn remove_sig(&mut self, sig_id: u64) -> Option<LibrarySig> {
        let sig = self.sigs.remove(&sig_id)?;

        let first_key = sig
            .pattern
            .initial_bytes
            .first()
            .map_or(0xFF, |pb| match pb {
                crate::PatternByte::Exact(b) => *b,
                crate::PatternByte::Wildcard => 0xFF,
            });

        if let Some(ids) = self.byte_index.get_mut(&first_key) {
            ids.retain(|&x| x != sig_id);
        }
        Some(sig)
    }

    /// Total number of signatures in the database.
    #[must_use] 
    pub fn sig_count(&self) -> usize {
        self.sigs.len()
    }

    // ── Search ────────────────────────────────────────────────────────────

    /// Search `buf` against the database using `params`.
    ///
    /// Returns a `LibraryReport` with all matching signatures sorted by
    /// descending combined confidence.
    #[must_use] 
    pub fn search(&self, buf: &[u8], params: &LibrarySearch) -> LibraryReport {
        let mut report = LibraryReport::default();

        // Determine candidate sig IDs from the byte index.
        let first = buf.first().copied().unwrap_or(0xFF);
        let mut candidates: Vec<u64> = Vec::new();
        if let Some(ids) = self.byte_index.get(&first) {
            candidates.extend_from_slice(ids);
        }
        // Also add wildcard-first signatures.
        if first != 0xFF
            && let Some(ids) = self.byte_index.get(&0xFF) {
                candidates.extend_from_slice(ids);
            }
        // Deduplicate
        candidates.sort_unstable();
        candidates.dedup();

        report.sigs_tested = candidates.len();

        for sig_id in &candidates {
            let Some(sig) = self.sigs.get(sig_id) else { continue };

            let Some(lib) = self.libraries.get(&sig.library_id) else { continue };

            // Apply search filters
            if let Some(ref name) = params.library_name
                && !lib.name.eq_ignore_ascii_case(name) {
                    continue;
                }
            if let Some(ref arch) = params.arch
                && &lib.arch != arch {
                    continue;
                }
            if let Some(ref os) = params.os
                && &lib.os != os {
                    continue;
                }

            // Initial byte match
            if !sig.pattern.matches_initial(buf) {
                continue;
            }
            report.initial_matches += 1;

            // CRC-16 + tail check
            if !sig.pattern.matches_crc16(buf) || !sig.pattern.matches_tail(buf) {
                continue;
            }

            // Compute pattern score
            let pattern_score = Self::compute_pattern_score(&sig.pattern, buf);
            let confidence = ConfidenceScore::compute(pattern_score, sig.weight);

            if !confidence.meets(params.min_confidence) {
                continue;
            }

            let func_name = sig
                .pattern
                .primary_name()
                .unwrap_or("unknown")
                .to_string();

            report.confirmed_matches += 1;

            let m = LibraryMatch {
                library: lib.clone(),
                sig: sig.clone(),
                function_name: func_name,
                confidence,
                offset: 0,
            };
            report.matches.push(m);

            let lib_name = lib.name.clone();
            if !report.matched_libraries.contains(&lib_name) {
                report.matched_libraries.push(lib_name);
            }
        }

        // Sort by descending combined confidence
        report.matches.sort_by(|a, b| {
            b.confidence
                .combined
                .partial_cmp(&a.confidence.combined)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        if params.best_only && !report.matches.is_empty() {
            report.matches.truncate(1);
        } else if let Some(max) = params.max_results {
            report.matches.truncate(max);
        }

        report
    }

    /// Search `buf` at every `step`-byte offset in [0, `buf.len()`).
    ///
    /// # Panics
    /// Panics if confidence scores contain NaN (should never occur in practice).
    #[must_use]
    pub fn search_sliding(
        &self,
        buf: &[u8],
        step: usize,
        params: &LibrarySearch,
    ) -> LibraryReport {
        let mut combined = LibraryReport::default();
        let step = step.max(1);
        let mut seen_sigs = std::collections::HashSet::new();

        for offset in (0..buf.len()).step_by(step) {
            let window = &buf[offset..];
            let mut sub = self.search(window, params);
            combined.sigs_tested += sub.sigs_tested;
            combined.initial_matches += sub.initial_matches;
            for mut m in sub.matches.drain(..) {
                if seen_sigs.insert(m.sig.sig_id) {
                    m.offset = offset;
                    combined.matches.push(m);
                    combined.confirmed_matches += 1;
                }
            }
            for lib in sub.matched_libraries {
                if !combined.matched_libraries.contains(&lib) {
                    combined.matched_libraries.push(lib);
                }
            }
            combined.warnings.extend(sub.warnings);
        }

        combined
            .matches
            .sort_by(|a, b| b.confidence.combined.partial_cmp(&a.confidence.combined).unwrap());
        if let Some(max) = params.max_results {
            combined.matches.truncate(max);
        }
        combined
    }

    // ── Bulk import / export ──────────────────────────────────────────────

    /// Import patterns from a slice of `(LibraryEntry, Vec<FlirtPattern>)`.
    ///
    /// Each unique `LibraryEntry` gets a fresh library ID; patterns are all
    /// added as signatures.  Returns `(libraries_added, sigs_added)`.
    pub fn import_batch(
        &mut self,
        items: Vec<(LibraryEntry, Vec<FlirtPattern>)>,
    ) -> (usize, usize) {
        let mut libs = 0;
        let mut sigs = 0;
        for (entry, patterns) in items {
            let lib_id = self.add_library(entry);
            libs += 1;
            for pat in patterns {
                if self.add_sig(lib_id, pat).is_ok() {
                    sigs += 1;
                }
            }
        }
        (libs, sigs)
    }

    /// Export all (library, signature) pairs where the library matches `name`.
    #[must_use] 
    pub fn export_by_library_name(&self, name: &str) -> Vec<(LibraryEntry, &LibrarySig)> {
        let key = name.to_lowercase();
        let Some(lib_ids) = self.name_index.get(&key) else { return Vec::new() };
        let mut out = Vec::with_capacity(self.sigs.len().min(lib_ids.len() * 8));
        for sig in self.sigs.values() {
            if lib_ids.contains(&sig.library_id)
                && let Some(lib) = self.libraries.get(&sig.library_id) {
                    out.push((lib.clone(), sig));
                }
        }
        out
    }

    // ── Statistics ────────────────────────────────────────────────────────

    /// Returns per-library signature counts as `(library_display_name, count)`.
    #[must_use] 
    pub fn sig_counts_per_library(&self) -> Vec<(String, usize)> {
        let mut counts: HashMap<u64, usize> = HashMap::new();
        for sig in self.sigs.values() {
            *counts.entry(sig.library_id).or_insert(0) += 1;
        }
        let mut result: Vec<(String, usize)> = counts
            .into_iter()
            .filter_map(|(id, cnt)| {
                self.libraries.get(&id).map(|e| (e.display_name(), cnt))
            })
            .collect();
        result.sort_by(|a, b| b.1.cmp(&a.1));
        result
    }

    /// Number of unique function names across all signatures.
    #[must_use] 
    pub fn unique_function_count(&self) -> usize {
        let mut names = std::collections::HashSet::new();
        for sig in self.sigs.values() {
            if let Some(n) = sig.pattern.primary_name() {
                names.insert(n.to_string());
            }
        }
        names.len()
    }

    // ── Internal helpers ──────────────────────────────────────────────────

    fn compute_pattern_score(pattern: &FlirtPattern, buf: &[u8]) -> f32 {
        // Base score: fraction of non-wildcard initial bytes that match
        let exact_count = pattern
            .initial_bytes
            .iter()
            .filter(|b| matches!(b, crate::PatternByte::Exact(_)))
            .count();
        let total = pattern.initial_bytes.len().max(1);
        let exact_f = f32::from(u8::try_from(exact_count).unwrap_or(u8::MAX));
        let total_f = f32::from(u8::try_from(total).unwrap_or(u8::MAX));
        let mut score = exact_f / total_f;

        // Penalize trivially short patterns: even a fully-exact 1-byte
        // pattern carries very little signal. Cap base score by a sigmoid
        // of concrete-byte count so single-byte patterns can never reach
        // 1.0 unaided.
        let length_factor = (exact_f / (exact_f + 4.0)).clamp(0.0, 1.0);
        score *= length_factor;

        // Bonus for CRC-16 match
        if pattern.crc_length > 0 && pattern.matches_crc16(buf) {
            score = (score + 0.2).min(1.0);
        }

        // Bonus for tail byte matches
        if !pattern.tail_bytes.is_empty() && pattern.matches_tail(buf) {
            score = (score + 0.1).min(1.0);
        }

        score
    }
}

impl Default for FlirtLibraryDatabase {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{FlirtName, FlirtPattern, PatternByte, TailByte};

    fn exact(b: u8) -> PatternByte {
        PatternByte::Exact(b)
    }
    fn wc() -> PatternByte {
        PatternByte::Wildcard
    }

    fn simple_pattern(first_bytes: &[u8]) -> FlirtPattern {
        let bytes: Vec<PatternByte> = first_bytes.iter().map(|&b| exact(b)).collect();
        let mut p = FlirtPattern::new(bytes);
        p.names.push(FlirtName {
            name: "test_func".to_string(),
            offset: 0,
            is_public: true,
            is_local: false,
        });
        p
    }

    fn make_entry(name: &str, version: &str) -> LibraryEntry {
        LibraryEntry::new(
            name,
            version,
            LibraryArch::X86_64,
            LibraryOs::Linux,
        )
    }

    // ── LibraryArch ───────────────────────────────────────────────────────

    #[test]
    fn test_arch_from_str_x86_64() {
        assert_eq!(LibraryArch::parse("x86_64"), LibraryArch::X86_64);
    }

    #[test]
    fn test_arch_from_str_amd64() {
        assert_eq!(LibraryArch::parse("amd64"), LibraryArch::X86_64);
    }

    #[test]
    fn test_arch_from_str_arm64() {
        assert_eq!(LibraryArch::parse("aarch64"), LibraryArch::Arm64);
    }

    #[test]
    fn test_arch_from_str_unknown() {
        assert_eq!(
            LibraryArch::parse("s390x"),
            LibraryArch::Unknown("s390x".to_string())
        );
    }

    #[test]
    fn test_arch_canonical() {
        assert_eq!(LibraryArch::X86_64.canonical(), "x86_64");
        assert_eq!(LibraryArch::Arm.canonical(), "arm");
    }

    // ── LibraryOs ─────────────────────────────────────────────────────────

    #[test]
    fn test_os_from_str_linux() {
        assert_eq!(LibraryOs::parse("linux"), LibraryOs::Linux);
    }

    #[test]
    fn test_os_from_str_windows() {
        assert_eq!(LibraryOs::parse("win64"), LibraryOs::Windows);
    }

    #[test]
    fn test_os_from_str_unknown() {
        assert_eq!(
            LibraryOs::parse("haiku"),
            LibraryOs::Unknown("haiku".to_string())
        );
    }

    #[test]
    fn test_os_canonical_bare() {
        assert_eq!(LibraryOs::Bare.canonical(), "bare");
    }

    // ── LibraryEntry ──────────────────────────────────────────────────────

    #[test]
    fn test_entry_display_name() {
        let e = make_entry("libc", "2.31");
        assert_eq!(e.display_name(), "libc-2.31 (x86_64/linux)");
    }

    #[test]
    fn test_entry_with_compiler() {
        let e = make_entry("openssl", "1.1.1k").with_compiler("gcc-9");
        assert_eq!(e.compiler.as_deref(), Some("gcc-9"));
    }

    #[test]
    fn test_entry_with_variant() {
        let e = make_entry("openssl", "1.1.1k").with_variant("debug");
        assert_eq!(e.variant.as_deref(), Some("debug"));
    }

    // ── FlirtLibraryDatabase – library management ─────────────────────────

    #[test]
    fn test_add_library() {
        let mut db = FlirtLibraryDatabase::new();
        let id = db.add_library(make_entry("libc", "2.31"));
        assert_eq!(db.library_count(), 1);
        assert!(db.get_library(id).is_some());
    }

    #[test]
    fn test_add_multiple_libraries() {
        let mut db = FlirtLibraryDatabase::new();
        let id1 = db.add_library(make_entry("libc", "2.31"));
        let id2 = db.add_library(make_entry("libm", "2.31"));
        assert_ne!(id1, id2);
        assert_eq!(db.library_count(), 2);
    }

    #[test]
    fn test_remove_library() {
        let mut db = FlirtLibraryDatabase::new();
        let id = db.add_library(make_entry("libc", "2.31"));
        let removed = db.remove_library(id);
        assert!(removed.is_some());
        assert_eq!(db.library_count(), 0);
    }

    #[test]
    fn test_remove_nonexistent_library() {
        let mut db = FlirtLibraryDatabase::new();
        assert!(db.remove_library(999).is_none());
    }

    #[test]
    fn test_iter_libraries() {
        let mut db = FlirtLibraryDatabase::new();
        db.add_library(make_entry("a", "1.0"));
        db.add_library(make_entry("b", "2.0"));
        let names: Vec<String> = db
            .iter_libraries()
            .map(|(_, e)| e.name.clone())
            .collect();
        assert!(names.contains(&"a".to_string()));
        assert!(names.contains(&"b".to_string()));
    }

    // ── Signature management ──────────────────────────────────────────────

    #[test]
    fn test_add_sig_ok() {
        let mut db = FlirtLibraryDatabase::new();
        let lib_id = db.add_library(make_entry("libc", "2.31"));
        let pat = simple_pattern(&[0x55, 0x48, 0x89, 0xE5]);
        let sig_id = db.add_sig(lib_id, pat).unwrap();
        assert!(sig_id > 0);
        assert_eq!(db.sig_count(), 1);
    }

    #[test]
    fn test_add_sig_unknown_library() {
        let mut db = FlirtLibraryDatabase::new();
        let pat = simple_pattern(&[0x55]);
        assert!(db.add_sig(999, pat).is_err());
    }

    #[test]
    fn test_remove_sig() {
        let mut db = FlirtLibraryDatabase::new();
        let lib_id = db.add_library(make_entry("libc", "2.31"));
        let pat = simple_pattern(&[0x55]);
        let sig_id = db.add_sig(lib_id, pat).unwrap();
        let removed = db.remove_sig(sig_id);
        assert!(removed.is_some());
        assert_eq!(db.sig_count(), 0);
    }

    #[test]
    fn test_remove_library_cascades_sigs() {
        let mut db = FlirtLibraryDatabase::new();
        let lib_id = db.add_library(make_entry("libc", "2.31"));
        db.add_sig(lib_id, simple_pattern(&[0x55])).unwrap();
        db.add_sig(lib_id, simple_pattern(&[0x56])).unwrap();
        db.remove_library(lib_id);
        assert_eq!(db.sig_count(), 0);
    }

    // ── Search ────────────────────────────────────────────────────────────

    #[test]
    fn test_search_basic_match() {
        let mut db = FlirtLibraryDatabase::new();
        let lib_id = db.add_library(make_entry("libc", "2.31"));
        let pat = simple_pattern(&[0x55, 0x48, 0x89, 0xE5]);
        db.add_sig(lib_id, pat).unwrap();
        let buf = vec![0x55u8, 0x48, 0x89, 0xE5, 0x00, 0x00];
        let report = db.search(&buf, &LibrarySearch::new());
        assert!(report.has_matches());
        assert_eq!(report.confirmed_matches, 1);
    }

    #[test]
    fn test_search_no_match() {
        let mut db = FlirtLibraryDatabase::new();
        let lib_id = db.add_library(make_entry("libc", "2.31"));
        let pat = simple_pattern(&[0x55, 0x48, 0x89, 0xE5]);
        db.add_sig(lib_id, pat).unwrap();
        let buf = vec![0xAAu8, 0xBB, 0xCC, 0xDD];
        let report = db.search(&buf, &LibrarySearch::new());
        assert!(!report.has_matches());
    }

    #[test]
    fn test_search_filter_by_library_name() {
        let mut db = FlirtLibraryDatabase::new();
        let id1 = db.add_library(make_entry("libc", "2.31"));
        let id2 = db.add_library(make_entry("libm", "2.31"));
        db.add_sig(id1, simple_pattern(&[0x55])).unwrap();
        db.add_sig(id2, simple_pattern(&[0x55])).unwrap();
        let buf = vec![0x55u8; 8];
        let params = LibrarySearch::new().with_library("libc");
        let report = db.search(&buf, &params);
        assert_eq!(report.confirmed_matches, 1);
        assert_eq!(report.matches[0].library.name, "libc");
    }

    #[test]
    fn test_search_filter_by_arch() {
        let mut db = FlirtLibraryDatabase::new();
        let e_x86 = LibraryEntry::new("libc", "2.31", LibraryArch::X86, LibraryOs::Linux);
        let e_x64 = LibraryEntry::new("libc", "2.31", LibraryArch::X86_64, LibraryOs::Linux);
        let id1 = db.add_library(e_x86);
        let id2 = db.add_library(e_x64);
        db.add_sig(id1, simple_pattern(&[0x55])).unwrap();
        db.add_sig(id2, simple_pattern(&[0x55])).unwrap();
        let buf = vec![0x55u8; 8];
        let params = LibrarySearch::new().with_arch(LibraryArch::X86);
        let report = db.search(&buf, &params);
        assert_eq!(report.confirmed_matches, 1);
        assert_eq!(report.matches[0].library.arch, LibraryArch::X86);
    }

    #[test]
    fn test_search_filter_min_confidence() {
        let mut db = FlirtLibraryDatabase::new();
        let lib_id = db.add_library(make_entry("libc", "2.31"));
        let pat = simple_pattern(&[0x55]);
        db.add_sig(lib_id, pat).unwrap();
        let buf = vec![0x55u8; 8];
        let params = LibrarySearch::new().with_min_confidence(0.99);
        let report = db.search(&buf, &params);
        // confidence will be less than 0.99 for a trivial pattern
        assert!(!report.has_matches());
    }

    #[test]
    fn test_search_best_only() {
        let mut db = FlirtLibraryDatabase::new();
        let lib_id = db.add_library(make_entry("libc", "2.31"));
        db.add_sig(lib_id, simple_pattern(&[0x55])).unwrap();
        db.add_sig(lib_id, simple_pattern(&[0x55, 0x48])).unwrap();
        let buf = vec![0x55u8, 0x48, 0x89, 0xE5];
        let params = LibrarySearch::new().best_only();
        let report = db.search(&buf, &params);
        assert!(report.matches.len() <= 1);
    }

    #[test]
    fn test_search_max_results() {
        let mut db = FlirtLibraryDatabase::new();
        let lib_id = db.add_library(make_entry("libc", "2.31"));
        for i in 0u8..5 {
            let mut p = simple_pattern(&[0x55]);
            p.names[0].name = format!("func_{i}");
            db.add_sig(lib_id, p).unwrap();
        }
        let buf = vec![0x55u8; 16];
        let params = LibrarySearch::new().with_max_results(2);
        let report = db.search(&buf, &params);
        assert!(report.matches.len() <= 2);
    }

    #[test]
    fn test_search_wildcard_pattern() {
        let mut db = FlirtLibraryDatabase::new();
        let lib_id = db.add_library(make_entry("libc", "2.31"));
        let mut pat = FlirtPattern::new(vec![exact(0x55), wc(), exact(0x89)]);
        pat.names.push(FlirtName {
            name: "wc_func".to_string(),
            offset: 0,
            is_public: true,
            is_local: false,
        });
        db.add_sig(lib_id, pat).unwrap();
        let buf = vec![0x55u8, 0xFF, 0x89, 0x00];
        let report = db.search(&buf, &LibrarySearch::new());
        assert!(report.has_matches());
    }

    #[test]
    fn test_search_with_tail_byte() {
        let mut db = FlirtLibraryDatabase::new();
        let lib_id = db.add_library(make_entry("libc", "2.31"));
        let mut pat = simple_pattern(&[0x55, 0x48]);
        pat.tail_bytes.push(TailByte {
            offset: 2,
            value: 0xC3,
        });
        db.add_sig(lib_id, pat).unwrap();
        let buf = vec![0x55u8, 0x48, 0xC3, 0x00];
        let report = db.search(&buf, &LibrarySearch::new());
        assert!(report.has_matches());
    }

    #[test]
    fn test_search_with_tail_byte_mismatch() {
        let mut db = FlirtLibraryDatabase::new();
        let lib_id = db.add_library(make_entry("libc", "2.31"));
        let mut pat = simple_pattern(&[0x55, 0x48]);
        pat.tail_bytes.push(TailByte {
            offset: 2,
            value: 0xC3,
        });
        db.add_sig(lib_id, pat).unwrap();
        let buf = vec![0x55u8, 0x48, 0xAA, 0x00];
        let report = db.search(&buf, &LibrarySearch::new());
        assert!(!report.has_matches());
    }

    // ── Sliding search ────────────────────────────────────────────────────

    #[test]
    fn test_search_sliding() {
        let mut db = FlirtLibraryDatabase::new();
        let lib_id = db.add_library(make_entry("libc", "2.31"));
        db.add_sig(lib_id, simple_pattern(&[0x55])).unwrap();
        let buf = vec![0x00u8, 0x00, 0x55, 0x48, 0x89, 0xE5];
        let params = LibrarySearch::new();
        let report = db.search_sliding(&buf, 1, &params);
        assert!(report.has_matches());
        let offsets: Vec<usize> = report.matches.iter().map(|m| m.offset).collect();
        assert!(offsets.contains(&2));
    }

    // ── Bulk import ───────────────────────────────────────────────────────

    #[test]
    fn test_import_batch() {
        let mut db = FlirtLibraryDatabase::new();
        let items = vec![
            (
                make_entry("libc", "2.31"),
                vec![simple_pattern(&[0x55]), simple_pattern(&[0x56])],
            ),
            (
                make_entry("libm", "2.31"),
                vec![simple_pattern(&[0x57])],
            ),
        ];
        let (libs, sigs) = db.import_batch(items);
        assert_eq!(libs, 2);
        assert_eq!(sigs, 3);
    }

    // ── Export ────────────────────────────────────────────────────────────

    #[test]
    fn test_export_by_library_name() {
        let mut db = FlirtLibraryDatabase::new();
        let id1 = db.add_library(make_entry("libc", "2.31"));
        let id2 = db.add_library(make_entry("libm", "2.31"));
        db.add_sig(id1, simple_pattern(&[0x55])).unwrap();
        db.add_sig(id2, simple_pattern(&[0x56])).unwrap();
        let results = db.export_by_library_name("libc");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0.name, "libc");
    }

    #[test]
    fn test_export_nonexistent_library() {
        let db = FlirtLibraryDatabase::new();
        let results = db.export_by_library_name("nonexistent");
        assert!(results.is_empty());
    }

    // ── Statistics ────────────────────────────────────────────────────────

    #[test]
    fn test_sig_counts_per_library() {
        let mut db = FlirtLibraryDatabase::new();
        let id1 = db.add_library(make_entry("libc", "2.31"));
        let id2 = db.add_library(make_entry("libm", "2.31"));
        db.add_sig(id1, simple_pattern(&[0x55])).unwrap();
        db.add_sig(id1, simple_pattern(&[0x56])).unwrap();
        db.add_sig(id2, simple_pattern(&[0x57])).unwrap();
        let counts = db.sig_counts_per_library();
        let libc_count = counts.iter().find(|(n, _)| n.starts_with("libc")).map(|(_, c)| *c);
        assert_eq!(libc_count, Some(2));
    }

    #[test]
    fn test_unique_function_count() {
        let mut db = FlirtLibraryDatabase::new();
        let id = db.add_library(make_entry("libc", "2.31"));
        let mut p1 = simple_pattern(&[0x55]);
        p1.names[0].name = "malloc".to_string();
        let mut p2 = simple_pattern(&[0x56]);
        p2.names[0].name = "free".to_string();
        let mut p3 = simple_pattern(&[0x57]);
        p3.names[0].name = "malloc".to_string(); // duplicate name
        db.add_sig(id, p1).unwrap();
        db.add_sig(id, p2).unwrap();
        db.add_sig(id, p3).unwrap();
        assert_eq!(db.unique_function_count(), 2);
    }

    // ── ConfidenceScore ───────────────────────────────────────────────────

    #[test]
    fn test_confidence_compute() {
        let c = ConfidenceScore::compute(0.8, 1.0);
        assert!((c.combined - 0.8).abs() < 1e-6);
    }

    #[test]
    fn test_confidence_clamped() {
        let c = ConfidenceScore::compute(1.5, 1.5);
        assert!(c.combined <= 1.0);
    }

    #[test]
    fn test_confidence_meets() {
        let c = ConfidenceScore::compute(0.7, 1.0);
        assert!(c.meets(0.5));
        assert!(!c.meets(0.8));
    }

    // ── LibraryReport ─────────────────────────────────────────────────────

    #[test]
    fn test_report_best_match() {
        let mut db = FlirtLibraryDatabase::new();
        let lib_id = db.add_library(make_entry("libc", "2.31"));
        db.add_sig(lib_id, simple_pattern(&[0x55])).unwrap();
        let buf = vec![0x55u8; 8];
        let report = db.search(&buf, &LibrarySearch::new());
        assert!(report.best_match().is_some());
    }

    #[test]
    fn test_report_summary_tuples() {
        let mut db = FlirtLibraryDatabase::new();
        let lib_id = db.add_library(make_entry("libc", "2.31"));
        let mut p = simple_pattern(&[0x55]);
        p.names[0].name = "malloc".to_string();
        db.add_sig(lib_id, p).unwrap();
        let buf = vec![0x55u8; 8];
        let report = db.search(&buf, &LibrarySearch::new());
        let tuples = report.summary_tuples();
        assert!(!tuples.is_empty());
        assert_eq!(tuples[0].0, "malloc");
    }

    #[test]
    fn test_report_confident_matches() {
        let mut db = FlirtLibraryDatabase::new();
        let lib_id = db.add_library(make_entry("libc", "2.31"));
        db.add_sig(lib_id, simple_pattern(&[0x55])).unwrap();
        let buf = vec![0x55u8; 8];
        let report = db.search(&buf, &LibrarySearch::new());
        // 0.0 threshold: all matches pass
        let count = report.confident_matches(0.0).count();
        assert_eq!(count, report.matches.len());
    }

    // ── LibrarySig ────────────────────────────────────────────────────────

    #[test]
    fn test_lib_sig_weight_clamped() {
        let p = simple_pattern(&[0x55]);
        let sig = LibrarySig::new(1, 1, p).with_weight(2.0);
        assert!(sig.weight <= 1.0);
    }

    #[test]
    fn test_lib_sig_source_file() {
        let p = simple_pattern(&[0x55]);
        let sig = LibrarySig::new(1, 1, p).with_source("libc.sig");
        assert_eq!(sig.source_file.as_deref(), Some("libc.sig"));
    }

    // ── Default ───────────────────────────────────────────────────────────

    #[test]
    fn test_default_db() {
        let db = FlirtLibraryDatabase::default();
        assert_eq!(db.library_count(), 0);
        assert_eq!(db.sig_count(), 0);
    }

    #[test]
    fn test_search_empty_db() {
        let db = FlirtLibraryDatabase::new();
        let report = db.search(&[0x55u8, 0x48], &LibrarySearch::new());
        assert!(!report.has_matches());
    }

    #[test]
    fn test_search_empty_buf() {
        let mut db = FlirtLibraryDatabase::new();
        let lib_id = db.add_library(make_entry("libc", "2.31"));
        db.add_sig(lib_id, simple_pattern(&[0x55])).unwrap();
        let report = db.search(&[], &LibrarySearch::new());
        assert!(!report.has_matches());
    }
}
