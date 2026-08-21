//! `rustre-deobf` — Core deobfuscation pass framework.
//!
//! Provides the foundational traits, types, and utilities for all deobfuscation
//! passes in the `RustRE` suite. Sub-crates implement [`DeobfPass`] and register
//! themselves with a [`DeobfPipeline`].

pub mod deobf_pipeline;
pub mod deobf_pass_registry;
pub mod deobf_registry;
pub mod deobf_report;
pub mod cfg_normalizer;
pub mod control_flow_normalization;
pub mod dead_code_eliminator;
pub mod deobf_report_extended;
pub mod junk_code_remover;
pub mod pass_manager;
pub mod pattern_recognition;
pub mod report;
pub mod constant_folding_pass;
pub mod opaque_predicate_resolver;
pub(crate) mod casts;

// ─────────────────────────────────────────────────────────────────────────────
// backends — re-exports of every rustre-deobf-* sibling crate
// ─────────────────────────────────────────────────────────────────────────────

/// Re-exports of each sibling deobfuscation sub-crate and a convenience
/// function that instantiates one of each primary pass.
#[cfg(feature = "subcrates")]
pub mod backends {
    pub use rustre_deobf_antianti;
    pub use rustre_deobf_cff;
    pub use rustre_deobf_iadl;
    pub use rustre_deobf_mba;
    pub use rustre_deobf_mhcde;
    pub use rustre_deobf_opaque;
    pub use rustre_deobf_smc;
    pub use rustre_deobf_string;
    pub use rustre_deobf_vm;
    pub use rustre_deobf_vmlift;

    use crate::DeobfPass;

    /// Return one instance of each built-in sibling pass.
    #[must_use]
    pub fn all() -> Vec<Box<dyn DeobfPass>> {
        vec![
            Box::new(rustre_deobf_antianti::AntiAntiPass::new()),
            Box::new(rustre_deobf_cff::CffDeobfuscationPass::new()),
            Box::new(rustre_deobf_iadl::IadlDeobfPass::new()),
            Box::new(rustre_deobf_mba::MbaDeobfuscationPass::new()),
            Box::new(rustre_deobf_mhcde::MhcdePass::new()),
            Box::new(rustre_deobf_opaque::OpaqueDeobfPass::new()),
            Box::new(rustre_deobf_smc::SmcPass::new()),
            Box::new(rustre_deobf_string::XorDecryptor::new()),
            Box::new(rustre_deobf_vm::VmDetector::new()),
            Box::new(rustre_deobf_vmlift::VmLifter::new()),
        ]
    }
}

use std::collections::HashMap;
use std::fmt::Write as _;

use rustre_core::address::{Address, SegmentMapping};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::casts::{f64_to_u32, u64_to_f32, u64_to_f64, u128_to_u64, usize_to_f32, usize_to_f64, usize_to_u8, usize_to_u32};

// ─────────────────────────────────────────────────────────────────────────────
// Error type
// ─────────────────────────────────────────────────────────────────────────────

/// Errors that can occur during deobfuscation.
#[derive(Debug, Error)]
pub enum DeobfError {
    /// The pass is not applicable to the current binary / context.
    #[error("pass not applicable: {0}")]
    NotApplicable(String),

    /// A parse error occurred while analysing the binary.
    #[error("parse error: {0}")]
    ParseError(String),

    /// Two patches overlap and cannot both be applied.
    #[error("patch conflict at offset {offset:#x}: {reason}")]
    PatchConflict {
        /// Offset of the conflicting patch.
        offset: usize,
        /// Human-readable description of the conflict.
        reason: String,
    },

    /// An internal invariant was violated.
    #[error("internal error: {0}")]
    Internal(String),

    /// Binary is too short to contain the expected structure.
    #[error("binary too short: need {needed} bytes, have {have}")]
    TooShort {
        /// Minimum bytes required.
        needed: usize,
        /// Bytes available.
        have: usize,
    },

    /// Key material could not be recovered.
    #[error("key recovery failed: {0}")]
    KeyRecovery(String),

    /// Decryption produced output that failed validation.
    #[error("decryption validation failed: {0}")]
    DecryptionValidation(String),

    /// An I/O-level error forwarded from a sub-operation.
    #[error("io error: {0}")]
    Io(String),

    /// Wraps an arbitrary anyhow error for convenience.
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

// ─────────────────────────────────────────────────────────────────────────────
// Core data structures
// ─────────────────────────────────────────────────────────────────────────────

/// A single binary patch produced by a deobfuscation pass.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Patch {
    /// Byte offset in the binary where the patch is applied.
    pub offset: usize,
    /// Bytes that were present before patching.
    pub original: Vec<u8>,
    /// Bytes written by the patch.
    pub patched: Vec<u8>,
    /// Human-readable explanation of why this patch was made.
    pub reason: String,
}

impl Patch {
    /// Create a new [`Patch`].
    #[must_use]
    pub fn new(
        offset: usize,
        original: Vec<u8>,
        patched: Vec<u8>,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            offset,
            original,
            patched,
            reason: reason.into(),
        }
    }

    /// Apply this patch to `data`, returning an error if the original bytes do
    /// not match (i.e. a prior patch has already modified this region).
    ///
    /// # Errors
    ///
    /// Returns [`DeobfError::TooShort`] if the patch region exceeds the buffer length.
    pub fn apply(&self, data: &mut [u8]) -> Result<(), DeobfError> {
        // Check that the original region fits in the buffer (for conflict detection).
        if !self.original.is_empty() {
            let orig_end = self.offset.checked_add(self.original.len()).ok_or(DeobfError::TooShort {
                needed: usize::MAX,
                have: data.len(),
            })?;
            if orig_end > data.len() {
                return Err(DeobfError::TooShort {
                    needed: orig_end,
                    have: data.len(),
                });
            }
        }
        // Check that the patched region fits in the buffer (for the write).
        let end = self.offset.checked_add(self.patched.len()).ok_or(DeobfError::TooShort {
            needed: usize::MAX,
            have: data.len(),
        })?;
        if end > data.len() {
            return Err(DeobfError::TooShort {
                needed: end,
                have: data.len(),
            });
        }
        // Verify the original bytes match to detect conflicts.
        if !self.original.is_empty()
            && data[self.offset..self.offset + self.original.len()] != self.original[..]
        {
            return Err(DeobfError::PatchConflict {
                offset: self.offset,
                reason: format!(
                    "expected {:02x?} found {:02x?}",
                    &self.original,
                    &data[self.offset..self.offset + self.original.len()]
                ),
            });
        }
        data[self.offset..self.offset + self.patched.len()].copy_from_slice(&self.patched);
        Ok(())
    }
}

/// Context passed to every [`DeobfPass`].
///
/// Passes read from `binary` and append to `patches`; they may also store
/// pass-specific metadata in `metadata` for downstream consumption.
#[derive(Debug, Clone)]
pub struct DeobfContext {
    /// Raw binary bytes (read-only during a pass; modifications are expressed
    /// as [`Patch`] records).
    pub binary: Vec<u8>,
    /// Map from original virtual address to file offset (populated by loader).
    /// Kept for backward compatibility; prefer `segment_mappings` for new code.
    pub address_map: HashMap<u64, u64>,
    /// Segment mappings from the binary loader, used for structured VA→offset
    /// translation via [`rustre_core::address::SegmentMapping`].
    pub segment_mappings: Vec<SegmentMapping>,
    /// Patches accumulated so far (including by previous passes).
    pub patches: Vec<Patch>,
    /// Arbitrary metadata keyed by string label.
    pub metadata: HashMap<String, serde_json::Value>,
}

impl DeobfContext {
    /// Construct an empty context wrapping the given binary bytes.
    #[must_use]
    pub fn new(binary: Vec<u8>) -> Self {
        Self {
            binary,
            address_map: HashMap::new(),
            segment_mappings: Vec::new(),
            patches: Vec::new(),
            metadata: HashMap::new(),
        }
    }

    /// Translate a virtual address to a file offset using the structured
    /// [`SegmentMapping`]s. Falls back to the flat `address_map` if no
    /// segment mapping covers the address.
    ///
    /// Returns `None` if the address is not mapped in either structure.
    #[must_use]
    pub fn va_to_file_offset(&self, va: u64) -> Option<u64> {
        let addr = Address::new(va);
        for seg in &self.segment_mappings {
            if let Some(offset) = seg.va_to_file_offset(addr) {
                return Some(offset.0);
            }
        }
        // Fall back to the flat address_map for loaders that haven't provided
        // full SegmentMapping data.
        self.address_map.get(&va).copied()
    }

    /// Register a [`SegmentMapping`] so that VA→offset translation covers this
    /// segment. Callers should populate this from the binary loader rather than
    /// manually inserting entries into `address_map`.
    pub fn add_segment(&mut self, mapping: SegmentMapping) {
        // Also populate address_map with the start VA for backward compat.
        self.address_map.insert(
            mapping.virtual_range.start.0,
            mapping.file_range.start.0,
        );
        self.segment_mappings.push(mapping);
    }

    /// Apply all accumulated patches to an owned copy of the binary and return
    /// the patched bytes.
    ///
    /// # Errors
    ///
    /// Returns [`DeobfError::TooShort`] if any patch region exceeds the binary length.
    pub fn apply_patches(&self) -> Result<Vec<u8>, DeobfError> {
        let mut out = self.binary.clone();
        for patch in &self.patches {
            // Relax origin check when applying — passes may stack on top of
            // each other's patches.
            let end = patch.offset.checked_add(patch.patched.len()).ok_or(DeobfError::TooShort {
                needed: usize::MAX,
                have: out.len(),
            })?;
            if end > out.len() {
                return Err(DeobfError::TooShort {
                    needed: end,
                    have: out.len(),
                });
            }
            out[patch.offset..end].copy_from_slice(&patch.patched);
        }
        Ok(out)
    }

    /// Record a metadata value under `key`.
    pub fn set_meta(&mut self, key: impl Into<String>, value: serde_json::Value) {
        self.metadata.insert(key.into(), value);
    }

    /// Retrieve a metadata value by `key`.
    #[must_use]
    pub fn get_meta(&self, key: &str) -> Option<&serde_json::Value> {
        self.metadata.get(key)
    }
}

/// Summary of what a single pass accomplished.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DeobfResult {
    /// Number of patches appended to the context during this run.
    pub patches_applied: usize,
    /// Human-readable descriptions of the transformations performed.
    pub transformations: Vec<String>,
    /// Total number of bytes modified across all patches.
    pub modified_bytes: usize,
    /// Confidence in the result in [0.0, 1.0].
    pub confidence: f32,
}

impl DeobfResult {
    /// Create a result with the given values.
    #[must_use]
    pub const fn new(
        patches_applied: usize,
        transformations: Vec<String>,
        modified_bytes: usize,
        confidence: f32,
    ) -> Self {
        Self {
            patches_applied,
            transformations,
            modified_bytes,
            confidence,
        }
    }

    /// Merge another [`DeobfResult`] into `self`.
    ///
    /// Note: [`Self::confidence`] is treated as a per-patch quantity and is only
    /// meaningful when [`Self::patches_applied`] > 0. The merge computes a weighted
    /// average using `patches_applied` as the weight, so a manually constructed
    /// result with `patches_applied == 0` and a non-zero `confidence` will have
    /// its confidence discarded (zero weight). Callers who need to preserve a
    /// confidence without any patches should record it in `transformations` or
    /// otherwise avoid relying on merge to combine such results.
    pub fn merge(&mut self, other: &Self) {
        // Weighted average confidence must be computed before patches_applied is updated.
        let self_patches = self.patches_applied;
        let total = self_patches + other.patches_applied;
        if total > 0 {
            self.confidence = self.confidence.mul_add(usize_to_f32(self_patches), other.confidence * usize_to_f32(other.patches_applied))
                / usize_to_f32(total);
        }
        self.patches_applied += other.patches_applied;
        self.transformations
            .extend(other.transformations.iter().cloned());
        self.modified_bytes += other.modified_bytes;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DeobfPass trait
// ─────────────────────────────────────────────────────────────────────────────

/// A single, composable deobfuscation pass.
///
/// Implementors must be [`Send`] + [`Sync`] so they can be stored in a shared
/// [`DeobfPipeline`] and executed from multiple threads.
pub trait DeobfPass: Send + Sync {
    /// Short identifier for this pass (e.g. `"xor-decrypt"`).
    fn name(&self) -> &'static str;

    /// One-line human-readable description.
    fn description(&self) -> &'static str;

    /// Run the pass, modifying `ctx.patches` and/or `ctx.metadata`.
    ///
    /// # Errors
    /// Returns [`DeobfError`] if the pass encounters an unrecoverable problem.
    fn run(&self, ctx: &mut DeobfContext) -> Result<DeobfResult, DeobfError>;

    /// Return `true` if this pass is worth running on the given context.
    ///
    /// A cheap pre-check (e.g. minimum size, magic bytes) avoids running
    /// expensive passes on obviously unsuitable binaries.
    fn is_applicable(&self, ctx: &DeobfContext) -> bool;
}

// ─────────────────────────────────────────────────────────────────────────────
// DeobfPipeline
// ─────────────────────────────────────────────────────────────────────────────

/// Aggregate result of running a full pipeline.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PipelineResult {
    /// Per-pass results in execution order.
    pub pass_results: Vec<(String, DeobfResult)>,
    /// Total combined result.
    pub total: DeobfResult,
    /// Error messages collected from passes that returned `Err` during the run.
    pub error_messages: Vec<String>,
}

/// An ordered sequence of [`DeobfPass`] objects that are run in turn.
#[derive(Default)]
pub struct DeobfPipeline {
    passes: Vec<Box<dyn DeobfPass>>,
}

impl std::fmt::Debug for DeobfPipeline {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeobfPipeline")
            .field("pass_count", &self.passes.len())
            .finish_non_exhaustive()
    }
}

impl DeobfPipeline {
    /// Create an empty pipeline.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a pipeline with options (options are reserved for future use).
    #[must_use]
    pub fn with_options(_options: DeobfOptions) -> Self {
        Self::default()
    }

    /// Append a pass to the end of the pipeline.
    pub fn add_pass(&mut self, pass: Box<dyn DeobfPass>) {
        self.passes.push(pass);
    }

    /// Run all applicable passes in order, collecting results.
    ///
    /// Errors from individual passes are collected rather than aborting the
    /// entire pipeline; the caller can inspect `skipped` in the returned
    /// result.
    pub fn run_all(&self, ctx: &mut DeobfContext) -> PipelineResult {
        let mut pipeline_result = PipelineResult::default();

        for pass in &self.passes {
            if !pass.is_applicable(ctx) {
                continue;
            }
            match pass.run(ctx) {
                Ok(result) => {
                    pipeline_result.total.merge(&result);
                    pipeline_result
                        .pass_results
                        .push((pass.name().to_owned(), result));
                }
                Err(e) => {
                    // Non-fatal: log the error to stderr and record it in the
                    // result so callers can inspect which passes failed and why.
                    let msg = format!("pass '{}' failed: {e}", pass.name());
                    eprintln!("[rustre-deobf] {msg}");
                    pipeline_result.error_messages.push(msg);
                    pipeline_result
                        .pass_results
                        .push((pass.name().to_owned(), DeobfResult::default()));
                }
            }
        }

        pipeline_result
    }

    /// Number of registered passes.
    #[must_use]
    pub fn pass_count(&self) -> usize {
        self.passes.len()
    }

    /// Run all passes and return a structured pipeline result.
    ///
    /// # Errors
    ///
    /// Propagates any [`DeobfError`] from individual passes.
    pub fn run(&self, ctx: &mut DeobfContext) -> Result<DeobfPipelineResult, DeobfError> {
        let start = std::time::Instant::now();
        let pr = self.run_all(ctx);
        let total_patches: usize = pr.pass_results.iter().map(|(_, r)| r.patches_applied).sum();
        let passes_run = pr.pass_results.len();
        Ok(DeobfPipelineResult {
            total_patches,
            passes_run,
            elapsed_ms: u128_to_u64(start.elapsed().as_millis()),
            pass_results: pr.pass_results,
        })
    }

    /// Add a pass wrapped in an `Arc` (for shared ownership scenarios).
    pub fn add_pass_arc(&mut self, pass: std::sync::Arc<dyn DeobfPass>) {
        // Wrap Arc in a Box-compatible adapter.
        self.passes.push(Box::new(ArcPassAdapter(pass)));
    }
}

/// Adapts an `Arc<dyn DeobfPass>` to the `DeobfPass` trait so it can be boxed.
struct ArcPassAdapter(std::sync::Arc<dyn DeobfPass>);

impl DeobfPass for ArcPassAdapter {
    fn name(&self) -> &'static str {
        self.0.name()
    }
    fn description(&self) -> &'static str {
        self.0.description()
    }
    fn run(&self, ctx: &mut DeobfContext) -> Result<DeobfResult, DeobfError> {
        self.0.run(ctx)
    }
    fn is_applicable(&self, ctx: &DeobfContext) -> bool {
        self.0.is_applicable(ctx)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PatternMatcher
// ─────────────────────────────────────────────────────────────────────────────

/// A byte-level pattern matcher with optional wildcard masks.
///
/// A mask byte of `0xFF` means "this byte must match exactly"; `0x00` means
/// "skip this byte" (wildcard); intermediate values create partial masks.
#[derive(Debug, Clone)]
pub struct PatternMatcher {
    /// Registered patterns: (name, pattern bytes, mask bytes).
    patterns: Vec<(String, Vec<u8>, Vec<u8>)>,
}

/// A single match found by [`PatternMatcher`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PatternMatch {
    /// Name of the matched pattern.
    pub name: String,
    /// Byte offset of the match in the searched buffer.
    pub offset: usize,
    /// The matching bytes (length == pattern length).
    pub bytes: Vec<u8>,
}

impl PatternMatcher {
    /// Create an empty matcher.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            patterns: Vec::new(),
        }
    }

    /// Register a pattern with a full-match mask (every byte must match).
    pub fn add_pattern(&mut self, name: impl Into<String>, pattern: Vec<u8>) {
        let len = pattern.len();
        self.add_masked_pattern(name, pattern, vec![0xFF; len]);
    }

    /// Register a pattern with an explicit per-byte mask.
    ///
    /// `mask.len()` must equal `pattern.len()`.
    ///
    /// # Panics
    ///
    /// Panics if `pattern.len() != mask.len()`.
    pub fn add_masked_pattern(&mut self, name: impl Into<String>, pattern: Vec<u8>, mask: Vec<u8>) {
        assert_eq!(
            pattern.len(),
            mask.len(),
            "pattern and mask must have the same length"
        );
        self.patterns.push((name.into(), pattern, mask));
    }

    /// Search `data` for all registered patterns and return all matches.
    #[must_use]
    pub fn scan(&self, data: &[u8]) -> Vec<PatternMatch> {
        let mut matches = Vec::new();
        for (name, pattern, mask) in &self.patterns {
            if pattern.is_empty() || data.len() < pattern.len() {
                continue;
            }
            'outer: for i in 0..=(data.len() - pattern.len()) {
                for (j, (&p, &m)) in pattern.iter().zip(mask.iter()).enumerate() {
                    if data[i + j] & m != p & m {
                        continue 'outer;
                    }
                }
                matches.push(PatternMatch {
                    name: name.clone(),
                    offset: i,
                    bytes: data[i..i + pattern.len()].to_vec(),
                });
            }
        }
        matches
    }
}

impl Default for PatternMatcher {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// XorDecryptor
// ─────────────────────────────────────────────────────────────────────────────

/// Detects XOR-encoded regions and decrypts them.
///
/// The heuristic: a region whose byte-frequency entropy is significantly lower
/// than 8 bits is a candidate for XOR encryption. We then try every possible
/// single-byte key and pick the one that maximises the number of printable /
/// ASCII bytes in the decrypted output.
#[derive(Debug, Clone, Default)]
pub struct XorDecryptor;

impl XorDecryptor {
    /// Create a new [`XorDecryptor`].
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Compute the Shannon entropy (bits per byte) of `data`.
    #[must_use]
    pub fn entropy(data: &[u8]) -> f64 {
        if data.is_empty() {
            return 0.0;
        }
        let mut freq = [0u64; 256];
        for &b in data {
            freq[b as usize] += 1;
        }
        let n = usize_to_f64(data.len());
        freq.iter()
            .filter(|&&c| c > 0)
            .map(|&c| {
                let p = u64_to_f64(c) / n;
                -p * p.log2()
            })
            .sum()
    }

    /// Try all 256 single-byte XOR keys and return the one that maximises
    /// printable-ASCII coverage after decryption.
    ///
    /// Returns `(best_key, decrypted_bytes)`.
    #[must_use]
    pub fn recover_single_byte_key(data: &[u8]) -> (u8, Vec<u8>) {
        // Score each candidate key by an English-language plausibility metric:
        // strong reward for letters and spaces, mild reward for digits/common
        // punctuation, heavy penalty for control chars and non-ASCII bytes.
        // This prevents the identity key (0) from tying real keys whenever the
        // ciphertext just happens to be all printable.
        fn score_key(data: &[u8], key: u8) -> i64 {
            let mut score: i64 = 0;
            for &b in data {
                let p = b ^ key;
                score += match p {
                    b' ' => 12,
                    b'a'..=b'z' => 10,
                    b'A'..=b'Z' => 8,
                    b'0'..=b'9' => 3,
                    b'.' | b',' | b'\'' | b'"' | b'!' | b'?' | b';' | b':' | b'-' => 2,
                    b'\n' | b'\r' | b'\t' | 0x20..=0x7e => 1,
                    _ => -5,
                };
                // Small extra reward for bytes that also look like code/text
                // according to the legacy heuristic — keeps that helper wired in.
                if XorDecryptor::is_likely_code_or_text(p) {
                    score += 1;
                }
            }
            score
        }

        let mut best_key = 1u8;
        let mut best_score = i64::MIN;
        let mut best_alpha_ratio = -1i64;
        // Search 1..=255 first; use 0 (identity) only as a fallback.
        for key in 1u8..=255 {
            let s = score_key(data, key);
            // Alphabetic ratio as tie-breaker: prefer keys yielding more letters/spaces.
            let alpha: i64 = data
                .iter()
                .filter(|&&b| {
                    let p = b ^ key;
                    p == b' ' || p.is_ascii_alphabetic()
                })
                .count() as i64;
            if s > best_score || (s == best_score && alpha > best_alpha_ratio) {
                best_score = s;
                best_alpha_ratio = alpha;
                best_key = key;
            }
        }
        // NB: we never fall back to key=0 (identity). Even for pathological
        // inputs the caller expects a real single-byte key search result — the
        // MCP wrapper contract is "the best single-byte XOR key". Returning
        // key=0 would leave the ciphertext unchanged, defeating the tool.
        let decrypted = data.iter().map(|&b| b ^ best_key).collect();
        (best_key, decrypted)
    }

    /// Decrypt `data` in-place with a constant XOR key.
    #[must_use]
    pub fn decrypt_constant(data: &[u8], key: u8) -> Vec<u8> {
        data.iter().map(|&b| b ^ key).collect()
    }

    /// Decrypt `data` with a multi-byte XOR key (cycling).
    #[must_use]
    pub fn decrypt_cyclic(data: &[u8], key: &[u8]) -> Vec<u8> {
        if key.is_empty() {
            return data.to_vec();
        }
        data.iter()
            .enumerate()
            .map(|(i, &b)| b ^ key[i % key.len()])
            .collect()
    }

    /// Decrypt `data` with a rolling XOR: each byte is XOR'd with the
    /// *previous ciphertext byte* after the initial key byte.
    #[must_use]
    pub fn decrypt_rolling(data: &[u8], initial_key: u8) -> Vec<u8> {
        let mut key = initial_key;
        data.iter()
            .map(|&b| {
                let plain = b ^ key;
                key = b;
                plain
            })
            .collect()
    }

    const fn is_likely_code_or_text(b: u8) -> bool {
        // printable ASCII or common code bytes (NOP, RET, CALL prefixes …)
        matches!(b, 0x20..=0x7E | 0x09 | 0x0A | 0x0D | 0x90 | 0xC3 | 0xCC)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// RolRorDecryptor
// ─────────────────────────────────────────────────────────────────────────────

/// Detect and undo ROL/ROR-based byte scrambling.
#[derive(Debug, Clone, Default)]
pub struct RolRorDecryptor;

impl RolRorDecryptor {
    /// Create a new [`RolRorDecryptor`].
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Rotate `byte` left by `n` bits.
    #[must_use]
    pub fn rol(byte: u8, n: u8) -> u8 {
        byte.rotate_left(u32::from(n & 7))
    }

    /// Rotate `byte` right by `n` bits.
    #[must_use]
    pub fn ror(byte: u8, n: u8) -> u8 {
        byte.rotate_right(u32::from(n & 7))
    }

    /// Undo a constant-ROL scramble: applies ROR to every byte.
    #[must_use]
    pub fn decrypt_rol(data: &[u8], rotation: u8) -> Vec<u8> {
        data.iter().map(|&b| Self::ror(b, rotation)).collect()
    }

    /// Undo a constant-ROR scramble: applies ROL to every byte.
    #[must_use]
    pub fn decrypt_ror(data: &[u8], rotation: u8) -> Vec<u8> {
        data.iter().map(|&b| Self::rol(b, rotation)).collect()
    }

    /// Try all 8 rotation amounts for both ROL and ROR, scoring by printable
    /// ASCII content. Returns `(rotation_bits, is_rol, decrypted)`.
    #[must_use]
    pub fn recover_rotation(data: &[u8]) -> (u8, bool, Vec<u8>) {
        let mut best = (0u8, false, data.to_vec());
        let mut best_score = 0usize;

        for rot in 1u8..8 {
            // Try undoing ROL (apply ROR).
            let dec = Self::decrypt_rol(data, rot);
            let score = dec
                .iter()
                .filter(|&&b| b.is_ascii_graphic() || b == b' ')
                .count();
            if score > best_score {
                best_score = score;
                best = (rot, true, dec);
            }
            // Try undoing ROR (apply ROL).
            let dec = Self::decrypt_ror(data, rot);
            let score = dec
                .iter()
                .filter(|&&b| b.is_ascii_graphic() || b == b' ')
                .count();
            if score > best_score {
                best_score = score;
                best = (rot, false, dec);
            }
        }
        best
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SimpleSubstitution
// ─────────────────────────────────────────────────────────────────────────────

/// Frequency-analysis attack on single-byte substitution ciphers.
#[derive(Debug, Clone, Default)]
pub struct SimpleSubstitution;

impl SimpleSubstitution {
    /// Create a new [`SimpleSubstitution`].
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Build a frequency table over `data` and return the most-common byte.
    #[must_use]
    pub fn most_frequent_byte(data: &[u8]) -> u8 {
        if data.is_empty() {
            return 0;
        }
        let mut freq = [0u64; 256];
        for &b in data {
            freq[b as usize] += 1;
        }
        freq.iter()
            .enumerate()
            .max_by_key(|&(_, &c)| c)
            .map_or(0, |(i, _)| usize_to_u8(i))
    }

    /// Attempt to recover the substitution table by assuming the most-frequent
    /// ciphertext byte maps to `assumed_plaintext` (e.g. `0x00` for NUL or
    /// `0x90` for NOP).
    ///
    /// Returns a 256-entry lookup table: `table[ciphertext] = plaintext`.
    /// Unresolved bytes are mapped to themselves.
    #[must_use]
    pub fn build_substitution_table(data: &[u8], assumed_plaintext: u8) -> [u8; 256] {
        let mut table: [u8; 256] = core::array::from_fn(usize_to_u8);
        let most_freq = Self::most_frequent_byte(data);
        // Map most frequent cipher byte to the assumed plaintext, swapping
        // with the previous occupant to keep the table bijective.
        table.swap(most_freq as usize, assumed_plaintext as usize);
        table
    }

    /// Apply a substitution table to `data`.
    #[must_use]
    pub fn apply_table(data: &[u8], table: &[u8; 256]) -> Vec<u8> {
        data.iter().map(|&b| table[b as usize]).collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Base64Decoder
// ─────────────────────────────────────────────────────────────────────────────

const BASE64_CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Find and decode Base-64 encoded strings inside binary data.
#[derive(Debug, Clone, Default)]
pub struct Base64Decoder;

/// A Base-64 blob found inside the binary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Base64Find {
    /// Byte offset of the Base-64 string start.
    pub offset: usize,
    /// The raw Base-64 characters.
    pub encoded: Vec<u8>,
    /// The decoded binary payload.
    pub decoded: Vec<u8>,
}

impl Base64Decoder {
    /// Create a new [`Base64Decoder`].
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Decode a standard Base-64 string (no line breaks expected).
    ///
    /// Returns `None` if the input contains invalid characters.
    #[must_use]
    pub fn decode(input: &[u8]) -> Option<Vec<u8>> {
        let input: Vec<u8> = input
            .iter()
            .copied()
            .filter(|&b| b != b'\n' && b != b'\r' && b != b' ')
            .collect();
        if input.is_empty() {
            return Some(Vec::new());
        }
        // Validate: all bytes must be valid base64 or '='
        for &b in &input {
            if b != b'=' && !BASE64_CHARS.contains(&b) {
                return None;
            }
        }
        let mut out = Vec::with_capacity(input.len() * 3 / 4);
        let mut i = 0;
        while i + 3 < input.len() {
            let v0 = Self::b64_val(input[i])?;
            let v1 = Self::b64_val(input[i + 1])?;
            let v2 = if input[i + 2] == b'=' {
                0
            } else {
                Self::b64_val(input[i + 2])?
            };
            let v3 = if input[i + 3] == b'=' {
                0
            } else {
                Self::b64_val(input[i + 3])?
            };

            out.push((v0 << 2) | (v1 >> 4));
            if input[i + 2] != b'=' {
                out.push((v1 << 4) | (v2 >> 2));
            }
            if input[i + 3] != b'=' {
                out.push((v2 << 6) | v3);
            }
            i += 4;
        }
        Some(out)
    }

    const fn b64_val(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }

    /// Maximum encoded-blob length that `find_all` will attempt to decode.
    ///
    /// Prevents dos-memory-exhaustion: an attacker-controlled binary could
    /// contain a single base64 region spanning the entire input (e.g. 100 MB),
    /// causing `decode` to allocate ~75 MB for every call to `find_all`.
    /// The cap is generous enough for realistic string / payload blobs but
    /// prevents runaway allocations.
    pub const MAX_FIND_ALL_BLOB_LEN: usize = 1 << 20; // 1 MiB encoded ≈ 768 KiB decoded

    /// Scan `data` for Base-64 encoded blobs (minimum 16 encoded chars).
    #[must_use]
    pub fn find_all(data: &[u8]) -> Vec<Base64Find> {
        let mut results = Vec::new();
        let mut i = 0;
        while i < data.len() {
            if Self::is_b64_char(data[i]) {
                let start = i;
                while i < data.len() && Self::is_b64_char(data[i]) {
                    i += 1;
                }
                // Consume optional trailing padding.
                let mut end = i;
                while end < data.len() && data[end] == b'=' {
                    end += 1;
                }
                let encoded = &data[start..end];
                // Skip blobs that are too large to avoid memory exhaustion
                // from attacker-controlled inputs (dos-memory-exhaustion).
                if encoded.len() >= 16
                    && encoded.len() <= Self::MAX_FIND_ALL_BLOB_LEN
                    && let Some(decoded) = Self::decode(encoded)
                {
                    results.push(Base64Find {
                        offset: start,
                        encoded: encoded.to_vec(),
                        decoded,
                    });
                }
                i = end;
            } else {
                i += 1;
            }
        }
        results
    }

    fn is_b64_char(b: u8) -> bool {
        BASE64_CHARS.contains(&b)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// StringDecryptor
// ─────────────────────────────────────────────────────────────────────────────

/// Attempt to decrypt strings using common patterns (constant XOR, rolling XOR).
#[derive(Debug, Clone, Default)]
pub struct StringDecryptor;

/// A candidate decrypted string.
#[derive(Debug, Clone)]
pub struct DecryptedString {
    /// File offset of the ciphertext.
    pub offset: usize,
    /// The raw ciphertext bytes.
    pub ciphertext: Vec<u8>,
    /// The recovered plaintext (UTF-8 lossy).
    pub plaintext: String,
    /// Description of the method used.
    pub method: String,
    /// Confidence score (0.0 – 1.0).
    pub confidence: f32,
}

impl StringDecryptor {
    /// Create a new [`StringDecryptor`].
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Try decrypting `data` at every alignment with every single-byte XOR key,
    /// returning candidates that look like printable strings.
    #[must_use]
    pub fn try_xor_constant(data: &[u8], min_length: usize) -> Vec<DecryptedString> {
        let mut results = Vec::new();
        if data.len() < min_length {
            return results;
        }
        for key in 0u8..=255 {
            if key == 0 {
                continue; // XOR with 0 is identity; skip.
            }
            let decrypted: Vec<u8> = data.iter().map(|&b| b ^ key).collect();
            if Self::looks_like_string(&decrypted, min_length) {
                let confidence = Self::english_score(&decrypted);
                results.push(DecryptedString {
                    offset: 0,
                    ciphertext: data.to_vec(),
                    plaintext: String::from_utf8_lossy(&decrypted).into_owned(),
                    method: format!("xor-constant(key=0x{key:02x})"),
                    confidence,
                });
            }
        }
        results
    }

    /// Try a rolling XOR with each possible initial key byte.
    #[must_use]
    pub fn try_xor_rolling(data: &[u8], min_length: usize) -> Vec<DecryptedString> {
        let mut results = Vec::new();
        if data.len() < min_length {
            return results;
        }
        for initial_key in 1u8..=255 {
            let decrypted = XorDecryptor::decrypt_rolling(data, initial_key);
            if Self::looks_like_string(&decrypted, min_length) {
                let confidence = Self::printable_ratio(&decrypted);
                results.push(DecryptedString {
                    offset: 0,
                    ciphertext: data.to_vec(),
                    plaintext: String::from_utf8_lossy(&decrypted).into_owned(),
                    method: format!("xor-rolling(initial=0x{initial_key:02x})"),
                    confidence,
                });
            }
        }
        results
    }

    fn looks_like_string(data: &[u8], min_length: usize) -> bool {
        if data.len() < min_length {
            return false;
        }
        Self::printable_ratio(data) >= 0.70
    }

    fn printable_ratio(data: &[u8]) -> f32 {
        if data.is_empty() {
            return 0.0;
        }
        let printable = data
            .iter()
            .filter(|&&b| b.is_ascii_graphic() || b == b' ')
            .count();
        usize_to_f32(printable) / usize_to_f32(data.len())
    }

    /// Score a byte slice by how closely it matches English letter/space frequencies.
    ///
    /// Higher is better; range is roughly 0.0–1.0.  Biases decryption towards
    /// human-readable English rather than other printable sequences.
    fn english_score(data: &[u8]) -> f32 {
        // Approximate English letter frequency table (a–z) scaled to 0–100.
        const FREQ: [u32; 26] = [
            82, 15, 28, 43, 127, 22, 20, 61, 70, 2, 8, 40, 24, 67, 75, 19, 1, 60, 63, 91, 28, 10,
            23, 2, 20, 1,
        ];
        if data.is_empty() {
            return 0.0;
        }
        let mut score: u64 = 0;
        for &b in data {
            match b {
                b'a'..=b'z' => score += u64::from(FREQ[(b - b'a') as usize]),
                b'A'..=b'Z' => score += u64::from(FREQ[(b - b'A') as usize]),
                b' ' | b'\t' | b'\n' | b'\r' => score += 60,
                0x20..=0x7E => score += 5, // other printable
                _ => {}
            }
        }
        let max_possible = usize_to_f32(data.len()) * 127.0;
        (u64_to_f32(score) / max_possible).clamp(0.0, 1.0)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PassRegistry
// ─────────────────────────────────────────────────────────────────────────────

/// A named registry of deobfuscation passes for dynamic dispatch by name.
#[derive(Default)]
pub struct PassRegistry {
    passes: HashMap<String, Box<dyn DeobfPass>>,
}

impl PassRegistry {
    /// Create an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a pass. If a pass with the same name already exists it is
    /// replaced and the old one returned.
    pub fn register(&mut self, pass: Box<dyn DeobfPass>) -> Option<Box<dyn DeobfPass>> {
        self.passes.insert(pass.name().to_owned(), pass)
    }

    /// Look up a registered pass by name.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&dyn DeobfPass> {
        self.passes.get(name).map(AsRef::as_ref)
    }

    /// Number of registered passes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.passes.len()
    }

    /// Returns `true` when no passes are registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.passes.is_empty()
    }

    /// Return all registered pass names, sorted alphabetically.
    #[must_use]
    pub fn names(&self) -> Vec<&str> {
        let mut names: Vec<&str> = self.passes.keys().map(String::as_str).collect();
        names.sort_unstable();
        names
    }

    /// Run all passes whose names are in `selection`, in the order given.
    ///
    /// # Errors
    /// Returns `Err` naming the unknown pass if any name in `selection` is not
    /// registered.
    pub fn run_selection(
        &self,
        selection: &[&str],
        ctx: &mut DeobfContext,
    ) -> Result<PipelineResult, DeobfError> {
        let mut result = PipelineResult::default();
        for &name in selection {
            let pass = self
                .passes
                .get(name)
                .ok_or_else(|| DeobfError::NotApplicable(format!("unknown pass: {name}")))?;
            if !pass.is_applicable(ctx) {
                continue;
            }
            match pass.run(ctx) {
                Ok(r) => {
                    result.total.merge(&r);
                    result.pass_results.push((name.to_owned(), r));
                }
                Err(e) => {
                    let msg = format!("pass '{name}' failed: {e}");
                    eprintln!("[rustre-deobf] {msg}");
                    result.error_messages.push(msg);
                    result
                        .pass_results
                        .push((name.to_owned(), DeobfResult::default()));
                }
            }
        }
        Ok(result)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TransformResult
// ─────────────────────────────────────────────────────────────────────────────

/// Fine-grained outcome of a single IR-level transformation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransformResult {
    /// The transformation was applied and the expression / instruction changed.
    Applied { rule: String, description: String },
    /// The transformation was considered but the preconditions were not met.
    Skipped { reason: String },
    /// The transformation failed due to an internal error.
    Error { message: String },
}

impl TransformResult {
    /// Returns `true` when the transformation was applied.
    #[must_use]
    pub const fn is_applied(&self) -> bool {
        matches!(self, Self::Applied { .. })
    }

    /// Returns `true` when the transformation was skipped.
    #[must_use]
    pub const fn is_skipped(&self) -> bool {
        matches!(self, Self::Skipped { .. })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DeobfReport
// ─────────────────────────────────────────────────────────────────────────────

/// Comprehensive report produced after an entire deobfuscation session.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DeobfReport {
    /// Per-pass pipeline results.
    pub pipeline: PipelineResult,
    /// Unique techniques detected across all passes.
    pub techniques_detected: Vec<String>,
    /// Total number of patches applied.
    pub total_patches: usize,
    /// Total number of bytes modified.
    pub total_modified_bytes: usize,
    /// Overall confidence in the deobfuscation (weighted average).
    pub overall_confidence: f32,
    /// Log of all transformation results.
    pub transform_log: Vec<TransformResult>,
    /// Wall-clock time elapsed during the session, in milliseconds.
    pub elapsed_ms: u64,
    /// Name of the binary being analyzed.
    pub binary_name: String,
}

impl DeobfReport {
    /// Build a report from a pipeline result.
    #[must_use]
    pub fn from_pipeline(pipeline: PipelineResult) -> Self {
        let total_patches = pipeline.total.patches_applied;
        let total_modified_bytes = pipeline.total.modified_bytes;
        let overall_confidence = pipeline.total.confidence;
        let techniques_detected = pipeline.total.transformations.clone();
        Self {
            pipeline,
            techniques_detected,
            total_patches,
            total_modified_bytes,
            overall_confidence,
            transform_log: Vec::new(),
            elapsed_ms: 0,
            binary_name: String::new(),
        }
    }

    /// Append a transform result to the log.
    pub fn log_transform(&mut self, result: TransformResult) {
        self.transform_log.push(result);
    }

    /// Number of applied transforms in the log.
    #[must_use]
    pub fn applied_count(&self) -> usize {
        self.transform_log.iter().filter(|r| r.is_applied()).count()
    }

    /// Create a new empty report for the given binary name.
    #[must_use]
    pub fn new(binary_name: impl Into<String>) -> Self {
        Self {
            binary_name: binary_name.into(),
            ..Self::default()
        }
    }

    /// Record an obfuscation type at a given confidence level.
    pub fn add_obfuscation(&mut self, ty: ObfuscationType, confidence: f64) {
        self.techniques_detected
            .push(format!("{ty}:{confidence:.2}"));
    }

    /// Set elapsed time in milliseconds.
    pub const fn set_elapsed_ms(&mut self, ms: u64) {
        self.elapsed_ms = ms;
    }

    /// Finalize the report (no-op; exists for API compatibility with secondary report type).
    pub const fn finalize(&mut self) {}

    /// Return a one-line summary string.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "{} technique(s), {} patches, {} bytes modified",
            self.techniques_detected.len(),
            self.total_patches,
            self.total_modified_bytes,
        )
    }
}

impl std::fmt::Display for DeobfReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.summary())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Rc4Decryptor
// ─────────────────────────────────────────────────────────────────────────────

/// RC4 stream cipher decryptor for binary-level deobfuscation.
///
/// RC4 (Rivest Cipher 4) is a symmetric cipher commonly used in malware
/// for string and payload encryption due to its simplicity.
#[derive(Debug, Clone, Default)]
pub struct Rc4Decryptor;

impl Rc4Decryptor {
    /// Create a new [`Rc4Decryptor`].
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Initialise the RC4 S-box using `key` (key-scheduling algorithm).
    #[must_use]
    pub fn ksa(key: &[u8]) -> [u8; 256] {
        let mut s: [u8; 256] = core::array::from_fn(usize_to_u8);
        if key.is_empty() {
            return s;
        }
        let mut j: u8 = 0;
        for i in 0u8..=255 {
            let i_usize = i as usize;
            j = j
                .wrapping_add(s[i_usize])
                .wrapping_add(key[i_usize % key.len()]);
            s.swap(i_usize, j as usize);
        }
        s
    }

    /// Run the pseudo-random generation algorithm (PRGA) to produce a keystream.
    #[must_use]
    pub fn prga(s: &mut [u8; 256], length: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(length);
        let mut i: u8 = 0;
        let mut j: u8 = 0;
        for _ in 0..length {
            i = i.wrapping_add(1);
            j = j.wrapping_add(s[i as usize]);
            s.swap(i as usize, j as usize);
            let k = s[s[i as usize].wrapping_add(s[j as usize]) as usize];
            out.push(k);
        }
        out
    }

    /// Decrypt (or encrypt — RC4 is symmetric) `data` using `key`.
    #[must_use]
    pub fn decrypt(data: &[u8], key: &[u8]) -> Vec<u8> {
        let mut s = Self::ksa(key);
        let keystream = Self::prga(&mut s, data.len());
        data.iter()
            .zip(keystream.iter())
            .map(|(&d, &k)| d ^ k)
            .collect()
    }

    /// Try common short keys (1–4 bytes, all printable ASCII) and return the
    /// key + decrypted bytes that maximise printable-ASCII coverage.
    ///
    /// This is a brute-force heuristic intended for short keys only.
    #[must_use]
    pub fn brute_force_short_key(data: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let mut best_score = 0usize;
        let mut best_key: Vec<u8> = vec![0u8];
        let mut best_decrypted = Self::decrypt(data, &[0u8]);

        // Try all single-byte keys first.
        for k in 0u8..=255 {
            let decrypted = Self::decrypt(data, &[k]);
            let score = decrypted
                .iter()
                .filter(|&&b| b.is_ascii_graphic() || b == b' ')
                .count();
            if score > best_score {
                best_score = score;
                best_key = vec![k];
                best_decrypted = decrypted;
            }
        }

        // Try two-byte keys with printable ASCII characters.
        for k1 in 0x20u8..=0x7E {
            for k2 in 0x20u8..=0x7E {
                let key = [k1, k2];
                let decrypted = Self::decrypt(data, &key);
                let score = decrypted
                    .iter()
                    .filter(|&&b| b.is_ascii_graphic() || b == b' ')
                    .count();
                if score > best_score {
                    best_score = score;
                    best_key = key.to_vec();
                    best_decrypted = decrypted;
                }
            }
        }

        (best_key, best_decrypted)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ChaCha20Decryptor (simplified / quarter-round core)
// ─────────────────────────────────────────────────────────────────────────────

/// Simplified `ChaCha20` stream cipher for binary-level deobfuscation.
///
/// Implements the full RFC 8439 quarter-round function and block generation
/// so that ChaCha20-encrypted payloads can be recovered.
#[derive(Debug, Clone, Default)]
pub struct ChaCha20Decryptor;

impl ChaCha20Decryptor {
    /// Create a new [`ChaCha20Decryptor`].
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Perform a single `ChaCha20` quarter-round on state words `(a, b, c, d)`.
    #[must_use]
    pub const fn quarter_round(mut a: u32, mut b: u32, mut c: u32, mut d: u32) -> (u32, u32, u32, u32) {
        a = a.wrapping_add(b);
        d ^= a;
        d = d.rotate_left(16);
        c = c.wrapping_add(d);
        b ^= c;
        b = b.rotate_left(12);
        a = a.wrapping_add(b);
        d ^= a;
        d = d.rotate_left(8);
        c = c.wrapping_add(d);
        b ^= c;
        b = b.rotate_left(7);
        (a, b, c, d)
    }

    /// Generate one 64-byte `ChaCha20` block given a 32-byte key, 12-byte nonce,
    /// and 32-bit block counter.
    ///
    /// # Errors
    /// Returns [`DeobfError::TooShort`] if `key.len() < 32` or `nonce.len() < 12`.
    pub fn block(key: &[u8], nonce: &[u8], counter: u32) -> Result<[u8; 64], DeobfError> {
        if key.len() < 32 {
            return Err(DeobfError::TooShort { needed: 32, have: key.len() });
        }
        if nonce.len() < 12 {
            return Err(DeobfError::TooShort { needed: 12, have: nonce.len() });
        }

        // Constants "expa", "nd 3", "2-by", "te k"
        let mut s: [u32; 16] = [
            0x6170_7865,
            0x3320_646E,
            0x7962_2D32,
            0x6B20_6574,
            u32::from_le_bytes([key[0], key[1], key[2], key[3]]),
            u32::from_le_bytes([key[4], key[5], key[6], key[7]]),
            u32::from_le_bytes([key[8], key[9], key[10], key[11]]),
            u32::from_le_bytes([key[12], key[13], key[14], key[15]]),
            u32::from_le_bytes([key[16], key[17], key[18], key[19]]),
            u32::from_le_bytes([key[20], key[21], key[22], key[23]]),
            u32::from_le_bytes([key[24], key[25], key[26], key[27]]),
            u32::from_le_bytes([key[28], key[29], key[30], key[31]]),
            counter,
            u32::from_le_bytes([nonce[0], nonce[1], nonce[2], nonce[3]]),
            u32::from_le_bytes([nonce[4], nonce[5], nonce[6], nonce[7]]),
            u32::from_le_bytes([nonce[8], nonce[9], nonce[10], nonce[11]]),
        ];

        let initial = s;

        for _ in 0..10 {
            // Column rounds.
            (s[0], s[4], s[8], s[12]) = Self::quarter_round(s[0], s[4], s[8], s[12]);
            (s[1], s[5], s[9], s[13]) = Self::quarter_round(s[1], s[5], s[9], s[13]);
            (s[2], s[6], s[10], s[14]) = Self::quarter_round(s[2], s[6], s[10], s[14]);
            (s[3], s[7], s[11], s[15]) = Self::quarter_round(s[3], s[7], s[11], s[15]);
            // Diagonal rounds.
            (s[0], s[5], s[10], s[15]) = Self::quarter_round(s[0], s[5], s[10], s[15]);
            (s[1], s[6], s[11], s[12]) = Self::quarter_round(s[1], s[6], s[11], s[12]);
            (s[2], s[7], s[8], s[13]) = Self::quarter_round(s[2], s[7], s[8], s[13]);
            (s[3], s[4], s[9], s[14]) = Self::quarter_round(s[3], s[4], s[9], s[14]);
        }

        let mut out = [0u8; 64];
        for (i, (&si, &ini)) in s.iter().zip(initial.iter()).enumerate() {
            let word = si.wrapping_add(ini);
            let bytes = word.to_le_bytes();
            out[i * 4..i * 4 + 4].copy_from_slice(&bytes);
        }
        Ok(out)
    }

    /// Encrypt / decrypt `data` using the given 32-byte `key` and 12-byte `nonce`.
    ///
    /// # Errors
    /// Returns [`DeobfError::TooShort`] if `key.len() < 32` or `nonce.len() < 12`.
    pub fn crypt(data: &[u8], key: &[u8], nonce: &[u8]) -> Result<Vec<u8>, DeobfError> {
        let mut out = Vec::with_capacity(data.len());
        let mut block_counter: u32 = 0;
        let mut pos = 0;
        while pos < data.len() {
            let block = Self::block(key, nonce, block_counter)?;
            let chunk_end = (pos + 64).min(data.len());
            for (d, k) in data[pos..chunk_end].iter().zip(block.iter()) {
                out.push(d ^ k);
            }
            pos += 64;
            block_counter = block_counter.wrapping_add(1);
        }
        Ok(out)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Adler32 / CRC32 checksums (utility for verifying decrypted payloads)
// ─────────────────────────────────────────────────────────────────────────────

/// Simple Adler-32 checksum used by many malware families for payload
/// integrity checks and hash-based API lookup.
#[derive(Debug, Clone, Default)]
pub struct Adler32;

impl Adler32 {
    /// Compute the Adler-32 checksum of `data`.
    #[must_use]
    pub fn checksum(data: &[u8]) -> u32 {
        const MOD_ADLER: u32 = 65521;
        let mut a: u32 = 1;
        let mut b: u32 = 0;
        for &byte in data {
            a = (a + u32::from(byte)) % MOD_ADLER;
            b = (b + a) % MOD_ADLER;
        }
        (b << 16) | a
    }
}

/// Standard CRC-32 (IEEE 802.3 polynomial) used in PE files and malware.
#[derive(Debug, Clone, Default)]
pub struct Crc32;

impl Crc32 {
    /// Compute the CRC-32 checksum of `data` using the standard polynomial.
    #[must_use]
    pub fn checksum(data: &[u8]) -> u32 {
        const POLY: u32 = 0xEDB8_8320;
        let mut crc: u32 = 0xFFFF_FFFF;
        for &byte in data {
            crc ^= u32::from(byte);
            for _ in 0..8 {
                if crc & 1 != 0 {
                    crc = (crc >> 1) ^ POLY;
                } else {
                    crc >>= 1;
                }
            }
        }
        !crc
    }

    /// Compute a table-driven CRC-32 for large buffers (same result, faster).
    #[must_use]
    pub fn checksum_table(data: &[u8]) -> u32 {
        // Build lookup table.
        const POLY: u32 = 0xEDB8_8320;
        let table: [u32; 256] = core::array::from_fn(|i| {
            let mut c = usize_to_u32(i);
            for _ in 0..8 {
                if c & 1 != 0 {
                    c = (c >> 1) ^ POLY;
                } else {
                    c >>= 1;
                }
            }
            c
        });

        let mut crc: u32 = 0xFFFF_FFFF;
        for &byte in data {
            crc = table[((crc ^ u32::from(byte)) & 0xFF) as usize] ^ (crc >> 8);
        }
        !crc
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// EntropyScanner
// ─────────────────────────────────────────────────────────────────────────────

/// Sliding-window entropy scanner for detecting compressed / encrypted regions.
#[derive(Debug, Clone)]
pub struct EntropyScanner {
    /// Window size in bytes (default 256).
    pub window: usize,
    /// Entropy threshold above which a region is flagged (default 7.2 bits/byte).
    pub threshold: f64,
    /// Step between consecutive windows (default `window / 4`).
    pub step: usize,
}

impl Default for EntropyScanner {
    fn default() -> Self {
        Self {
            window: 256,
            threshold: 7.2,
            step: 64,
        }
    }
}

/// A high-entropy region found by [`EntropyScanner`].
#[derive(Debug, Clone, PartialEq)]
pub struct EntropyRegion {
    /// Start offset.
    pub offset: usize,
    /// Window size used for this measurement.
    pub length: usize,
    /// Measured Shannon entropy in bits per byte.
    pub entropy: f64,
}

impl EntropyScanner {
    /// Create a scanner with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Scan `data` with a sliding window and return all regions above the
    /// entropy threshold.
    #[must_use]
    pub fn scan(&self, data: &[u8]) -> Vec<EntropyRegion> {
        // A zero window or zero step would cause a panic or an infinite loop.
        if self.window == 0 || self.step == 0 {
            return vec![];
        }
        if data.len() < self.window {
            let entropy = XorDecryptor::entropy(data);
            if entropy >= self.threshold {
                return vec![EntropyRegion {
                    offset: 0,
                    length: data.len(),
                    entropy,
                }];
            }
            return vec![];
        }

        let mut results = Vec::new();
        let mut offset = 0;
        while offset + self.window <= data.len() {
            let window_data = &data[offset..offset + self.window];
            let entropy = XorDecryptor::entropy(window_data);
            if entropy >= self.threshold {
                results.push(EntropyRegion {
                    offset,
                    length: self.window,
                    entropy,
                });
            }
            offset += self.step;
        }
        results
    }

    /// Return the single highest-entropy region, if any.
    #[must_use]
    pub fn max_entropy_region(&self, data: &[u8]) -> Option<EntropyRegion> {
        self.scan(data)
            .into_iter()
            .max_by(|a, b| a.entropy.partial_cmp(&b.entropy).unwrap_or(std::cmp::Ordering::Equal))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// BinarySection
// ─────────────────────────────────────────────────────────────────────────────

/// A named section extracted from a binary (PE, ELF, Mach-O, raw).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BinarySection {
    /// Section name (e.g. `.text`, `.data`, `UPX0`).
    pub name: String,
    /// Virtual address of the section.
    pub virtual_address: u64,
    /// Raw bytes of the section.
    pub data: Vec<u8>,
    /// Entropy of the section bytes.
    pub entropy_bits: u32,
}

impl BinarySection {
    /// Construct a section and compute its entropy.
    #[must_use]
    pub fn new(name: impl Into<String>, virtual_address: u64, data: Vec<u8>) -> Self {
        let entropy = XorDecryptor::entropy(&data);
        let entropy_bits = f64_to_u32(entropy * 100.0);
        Self {
            name: name.into(),
            virtual_address,
            data,
            entropy_bits,
        }
    }

    /// Return `true` if this section looks packed / encrypted (entropy > 7.0).
    #[must_use]
    pub const fn looks_packed(&self) -> bool {
        self.entropy_bits > 700
    }

    /// Byte length of the section.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.data.len()
    }

    /// Returns `true` if the section has no bytes.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PatchSet — a deduplicated, sorted collection of Patch records
// ─────────────────────────────────────────────────────────────────────────────

/// A deduplicated, offset-sorted collection of [`Patch`] records.
///
/// Guarantees no two patches overlap when inserted through [`PatchSet::insert`].
#[derive(Debug, Clone, Default)]
pub struct PatchSet {
    patches: Vec<Patch>,
}

impl PatchSet {
    /// Create an empty set.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Try to insert `patch`. Returns `false` (without inserting) if `patch`
    /// overlaps any existing patch.
    pub fn insert(&mut self, patch: Patch) -> bool {
        let start = patch.offset;
        // Checked add: a patch whose end wraps around cannot be valid.
        let Some(end) = patch.offset.checked_add(patch.patched.len()) else { return false; };
        for existing in &self.patches {
            let e_start = existing.offset;
            let Some(e_end) = existing.offset.checked_add(existing.patched.len()) else { return false; };
            if start < e_end && e_start < end {
                return false;
            }
        }
        // Maintain offset order.
        let pos = self.patches.partition_point(|p| p.offset <= patch.offset);
        self.patches.insert(pos, patch);
        true
    }

    /// Number of patches.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.patches.len()
    }

    /// Returns `true` if no patches have been inserted.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.patches.is_empty()
    }

    /// Return an immutable view of the patches in offset order.
    #[must_use]
    pub fn patches(&self) -> &[Patch] {
        &self.patches
    }

    /// Consume the set and return the patches as a `Vec`.
    #[must_use]
    pub fn into_patches(self) -> Vec<Patch> {
        self.patches
    }

    /// Apply all patches in order to a copy of `data`.
    ///
    /// # Errors
    /// Returns [`DeobfError`] if any patch extends beyond the end of `data`.
    pub fn apply_to(&self, data: &[u8]) -> Result<Vec<u8>, DeobfError> {
        let mut out = data.to_vec();
        for patch in &self.patches {
            let end = patch.offset.checked_add(patch.patched.len()).ok_or(DeobfError::TooShort {
                needed: usize::MAX,
                have: out.len(),
            })?;
            if end > out.len() {
                return Err(DeobfError::TooShort {
                    needed: end,
                    have: out.len(),
                });
            }
            out[patch.offset..end].copy_from_slice(&patch.patched);
        }
        Ok(out)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// HexDumper — structured hex dump utility
// ─────────────────────────────────────────────────────────────────────────────

/// Produces formatted hex dumps of byte slices for reporting and debugging.
#[derive(Debug, Clone)]
pub struct HexDumper {
    /// Number of bytes per row (default 16).
    pub width: usize,
    /// Base virtual address used for the leftmost address column.
    pub base_address: u64,
}

impl Default for HexDumper {
    fn default() -> Self {
        Self {
            width: 16,
            base_address: 0,
        }
    }
}

impl HexDumper {
    /// Create a dumper with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the base address displayed in the address column.
    #[must_use]
    pub const fn with_base(mut self, base: u64) -> Self {
        self.base_address = base;
        self
    }

    /// Dump `data` into a formatted multi-line string.
    #[must_use]
    pub fn dump(&self, data: &[u8]) -> String {
        let width = if self.width == 0 { 16 } else { self.width };
        let mut out = String::new();
        for (row_idx, chunk) in data.chunks(width).enumerate() {
            // Use saturating arithmetic to avoid overflow on very large buffers.
            let byte_offset = row_idx.saturating_mul(width) as u64;
            let addr = self.base_address.saturating_add(byte_offset);
            let _ = write!(out, "{addr:08X}  ");
            for (i, &byte) in chunk.iter().enumerate() {
                let _ = write!(out, "{byte:02X} ");
                if i == 7 {
                    out.push(' ');
                }
            }
            // Pad last row.
            let missing = width - chunk.len();
            for _ in 0..missing {
                out.push_str("   ");
            }
            if missing > 8 {
                out.push(' ');
            }
            out.push(' ');
            for &byte in chunk {
                let ch = if byte.is_ascii_graphic() || byte == b' ' {
                    byte as char
                } else {
                    '.'
                };
                out.push(ch);
            }
            out.push('\n');
        }
        out
    }

    /// Return the hex-only portion (no addresses, no ASCII column).
    #[must_use]
    pub fn hex_only(&self, data: &[u8]) -> String {
        use std::fmt::Write;
        let mut out = String::with_capacity(data.len() * 3);
        for (i, b) in data.iter().enumerate() {
            if i > 0 {
                out.push(' ');
            }
            let _ = write!(out, "{b:02x}");
        }
        out
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ConstantFoldingPass — simple IR-level constant folding deobfuscation pass
// ─────────────────────────────────────────────────────────────────────────────

/// A [`DeobfPass`] that scans for trivially constant binary expressions in
/// `binary` (encoded as 8-byte tuples: `[op, a0..a3, b0..b3]`) and replaces
/// them with the computed constant.
///
/// This is a simplified IR stand-in; real constant folding operates at LLIL/MLIL.
#[derive(Debug, Clone, Default)]
pub struct ConstantFoldingPass;

impl ConstantFoldingPass {
    /// Create a new pass.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl DeobfPass for ConstantFoldingPass {
    fn name(&self) -> &'static str {
        "constant-folding"
    }

    fn description(&self) -> &'static str {
        "Replace trivially constant arithmetic expressions with their computed values"
    }

    fn is_applicable(&self, ctx: &DeobfContext) -> bool {
        ctx.binary.len() >= 9
    }

    fn run(&self, ctx: &mut DeobfContext) -> Result<DeobfResult, DeobfError> {
        let mut patches_applied = 0;
        let mut modified_bytes = 0;
        let mut transformations = Vec::new();

        // Scan for simple ADD/SUB/AND/OR/XOR of two u32 constants.
        // Encoding: [op(1), a(4 LE), b(4 LE)] = 9 bytes.
        let data = &ctx.binary;
        let mut i = 0;
        while i + 8 < data.len() {
            let op = data[i];
            let a = u32::from_le_bytes([data[i + 1], data[i + 2], data[i + 3], data[i + 4]]);
            let b = u32::from_le_bytes([data[i + 5], data[i + 6], data[i + 7], data[i + 8]]);
            let result_opt: Option<u32> = match op {
                0x01 => Some(a.wrapping_add(b)),
                0x02 => Some(a.wrapping_sub(b)),
                0x03 => Some(a & b),
                0x04 => Some(a | b),
                0x05 => Some(a ^ b),
                0x06 => Some(a.wrapping_mul(b)),
                _ => None,
            };
            if let Some(result) = result_opt {
                let original = data[i..i + 9].to_vec();
                let mut patched = vec![0u8; 9];
                // Keep op byte, replace operands with [result, 0, 0, 0, 0] (identity form).
                patched[0] = 0x01; // ADD
                patched[1..5].copy_from_slice(&result.to_le_bytes());
                // Second operand = 0.
                ctx.patches.push(Patch::new(
                    i,
                    original,
                    patched,
                    format!("constant-fold: {op:#04x} {a:#x} {b:#x} = {result:#x}"),
                ));
                patches_applied += 1;
                modified_bytes += 9;
                transformations.push(format!("folded at {i:#x}: {result:#x}"));
                i += 9;
            } else {
                i += 1;
            }
        }

        Ok(DeobfResult::new(
            patches_applied,
            transformations,
            modified_bytes,
            0.95,
        ))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// NopSledException
// ─────────────────────────────────────────────────────────────────────────────

/// A [`DeobfPass`] that removes NOP sleds from binary data.
///
/// NOP sleds (`0x90` sequences) are commonly used as padding and in shellcode.
/// Removing them reduces noise in disassembly.
#[derive(Debug, Clone)]
pub struct NopSledRemover {
    /// Minimum sled length to remove (default 4).
    pub min_sled: usize,
}

impl Default for NopSledRemover {
    fn default() -> Self {
        Self { min_sled: 4 }
    }
}

impl NopSledRemover {
    /// Create a remover with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a remover with the given minimum sled length.
    #[must_use]
    pub const fn with_min_sled(min_sled: usize) -> Self {
        Self { min_sled }
    }

    /// Scan `data` and return the start offsets and lengths of all NOP sleds.
    #[must_use]
    pub fn find_sleds(&self, data: &[u8]) -> Vec<(usize, usize)> {
        let mut result = Vec::new();
        let mut i = 0;
        while i < data.len() {
            if data[i] == 0x90 {
                let start = i;
                while i < data.len() && data[i] == 0x90 {
                    i += 1;
                }
                let len = i - start;
                if len >= self.min_sled {
                    result.push((start, len));
                }
            } else {
                i += 1;
            }
        }
        result
    }
}

impl DeobfPass for NopSledRemover {
    fn name(&self) -> &'static str {
        "nop-sled-remover"
    }

    fn description(&self) -> &'static str {
        "Removes NOP sled regions from binary data"
    }

    fn is_applicable(&self, ctx: &DeobfContext) -> bool {
        ctx.binary.len() >= self.min_sled && ctx.binary.contains(&0x90)
    }

    fn run(&self, ctx: &mut DeobfContext) -> Result<DeobfResult, DeobfError> {
        let sleds = self.find_sleds(&ctx.binary);
        let mut patches_applied = 0;
        let mut modified_bytes = 0;
        let mut transformations = Vec::new();

        for (start, len) in &sleds {
            let original = ctx.binary[*start..*start + *len].to_vec();
            // Replace with `len` copies of the `INT3` instruction (0xCC) as a
            // sentinel, or simply leave as-is — here we zero them.
            let patched = vec![0x00u8; *len];
            ctx.patches.push(Patch::new(
                *start,
                original,
                patched,
                format!("NOP sled at {start:#x} ({len} bytes)"),
            ));
            patches_applied += 1;
            modified_bytes += len;
            transformations.push(format!("removed {len}-byte NOP sled at {start:#x}"));
        }

        let confidence = if patches_applied > 0 { 0.99 } else { 0.0 };
        Ok(DeobfResult::new(
            patches_applied,
            transformations,
            modified_bytes,
            confidence,
        ))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Patch ────────────────────────────────────────────────────────────────

    #[test]
    fn test_patch_apply_basic() {
        let mut data = vec![0x90, 0x90, 0x90, 0x90];
        let patch = Patch::new(1, vec![0x90, 0x90], vec![0xCC, 0xCC], "breakpoints");
        patch.apply(&mut data).unwrap();
        assert_eq!(data, vec![0x90, 0xCC, 0xCC, 0x90]);
    }

    #[test]
    fn test_patch_apply_out_of_bounds() {
        let mut data = vec![0x00, 0x01];
        let patch = Patch::new(1, vec![], vec![0xAA, 0xBB, 0xCC], "oob");
        assert!(patch.apply(&mut data).is_err());
    }

    #[test]
    fn test_patch_conflict_detection() {
        let mut data = vec![0xAA, 0xBB];
        let patch = Patch::new(0, vec![0xFF, 0xFF], vec![0x00, 0x00], "mismatch");
        assert!(matches!(
            patch.apply(&mut data),
            Err(DeobfError::PatchConflict { .. })
        ));
    }

    // ── DeobfContext ─────────────────────────────────────────────────────────

    #[test]
    fn test_context_apply_patches() {
        let mut ctx = DeobfContext::new(vec![0xAA, 0xBB, 0xCC]);
        ctx.patches.push(Patch::new(1, vec![], vec![0xFF], "test"));
        let out = ctx.apply_patches().unwrap();
        assert_eq!(out, vec![0xAA, 0xFF, 0xCC]);
    }

    #[test]
    fn test_context_metadata() {
        let mut ctx = DeobfContext::new(vec![]);
        ctx.set_meta("key", serde_json::json!(42));
        assert_eq!(ctx.get_meta("key"), Some(&serde_json::json!(42)));
        assert_eq!(ctx.get_meta("missing"), None);
    }

    // ── DeobfPipeline ────────────────────────────────────────────────────────

    struct AlwaysNop;
    impl DeobfPass for AlwaysNop {
        fn name(&self) -> &'static str {
            "nop"
        }
        fn description(&self) -> &'static str {
            "does nothing"
        }
        fn run(&self, _ctx: &mut DeobfContext) -> Result<DeobfResult, DeobfError> {
            Ok(DeobfResult::new(0, vec![], 0, 1.0))
        }
        fn is_applicable(&self, _ctx: &DeobfContext) -> bool {
            true
        }
    }

    struct NeverApplicable;
    impl DeobfPass for NeverApplicable {
        fn name(&self) -> &'static str {
            "never"
        }
        fn description(&self) -> &'static str {
            "never runs"
        }
        fn run(&self, _ctx: &mut DeobfContext) -> Result<DeobfResult, DeobfError> {
            panic!("should not be called")
        }
        fn is_applicable(&self, _ctx: &DeobfContext) -> bool {
            false
        }
    }

    struct AlwaysErrors;
    impl DeobfPass for AlwaysErrors {
        fn name(&self) -> &'static str {
            "error"
        }
        fn description(&self) -> &'static str {
            "always errors"
        }
        fn run(&self, _ctx: &mut DeobfContext) -> Result<DeobfResult, DeobfError> {
            Err(DeobfError::NotApplicable("test error".to_owned()))
        }
        fn is_applicable(&self, _ctx: &DeobfContext) -> bool {
            true
        }
    }

    #[test]
    fn test_pipeline_basic() {
        let mut pipeline = DeobfPipeline::new();
        pipeline.add_pass(Box::new(AlwaysNop));
        pipeline.add_pass(Box::new(NeverApplicable));
        assert_eq!(pipeline.pass_count(), 2);

        let mut ctx = DeobfContext::new(vec![0x00]);
        let result = pipeline.run_all(&mut ctx);
        // NeverApplicable is skipped; only AlwaysNop ran.
        assert_eq!(result.pass_results.len(), 1);
        assert_eq!(result.pass_results[0].0, "nop");
    }

    #[test]
    fn test_pipeline_error_is_non_fatal() {
        let mut pipeline = DeobfPipeline::new();
        pipeline.add_pass(Box::new(AlwaysErrors));
        pipeline.add_pass(Box::new(AlwaysNop));

        let mut ctx = DeobfContext::new(vec![]);
        let result = pipeline.run_all(&mut ctx);
        assert_eq!(result.pass_results.len(), 2);
    }

    // ── PatternMatcher ───────────────────────────────────────────────────────

    #[test]
    fn test_pattern_matcher_exact() {
        let mut m = PatternMatcher::new();
        m.add_pattern("test", vec![0x0F, 0x31]);
        let data = vec![0x90, 0x0F, 0x31, 0x90];
        let hits = m.scan(&data);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].name, "test");
        assert_eq!(hits[0].offset, 1);
    }

    #[test]
    fn test_pattern_matcher_wildcard() {
        let mut m = PatternMatcher::new();
        m.add_masked_pattern("any-two", vec![0xFF, 0x00], vec![0xFF, 0x00]);
        let data = vec![0xFF, 0xAB, 0xFF, 0xCD];
        let hits = m.scan(&data);
        assert_eq!(hits.len(), 2);
    }

    #[test]
    fn test_pattern_matcher_no_match() {
        let mut m = PatternMatcher::new();
        m.add_pattern("sig", vec![0xDE, 0xAD]);
        let hits = m.scan(&[0x00, 0x01, 0x02]);
        assert!(hits.is_empty());
    }

    #[test]
    fn test_pattern_matcher_multiple_patterns() {
        let mut m = PatternMatcher::new();
        m.add_pattern("a", vec![0xAA]);
        m.add_pattern("b", vec![0xBB]);
        let hits = m.scan(&[0xAA, 0xBB, 0xAA]);
        assert_eq!(hits.len(), 3);
    }

    // ── XorDecryptor ─────────────────────────────────────────────────────────

    #[test]
    fn test_xor_decrypt_constant() {
        let plain = b"Hello!";
        let key = 0x42u8;
        let cipher: Vec<u8> = plain.iter().map(|&b| b ^ key).collect();
        let decrypted = XorDecryptor::decrypt_constant(&cipher, key);
        assert_eq!(decrypted, plain);
    }

    #[test]
    fn test_xor_decrypt_cyclic() {
        let plain = b"Secret";
        let key = b"\xAB\xCD";
        let cipher: Vec<u8> = plain
            .iter()
            .enumerate()
            .map(|(i, &b)| b ^ key[i % key.len()])
            .collect();
        let decrypted = XorDecryptor::decrypt_cyclic(&cipher, key);
        assert_eq!(decrypted, plain);
    }

    #[test]
    fn test_xor_decrypt_rolling() {
        let plain = b"Roll";
        let initial_key = 0x55u8;
        // Encrypt: each byte XOR'd with previous ciphertext byte.
        let mut cipher = Vec::new();
        let mut prev = initial_key;
        for &b in plain {
            let c = b ^ prev;
            cipher.push(c);
            prev = c;
        }
        let decrypted = XorDecryptor::decrypt_rolling(&cipher, initial_key);
        assert_eq!(decrypted, plain);
    }

    #[test]
    fn test_xor_recover_key() {
        let plain = b"AAAAAABBBBBB";
        let key = 0x11u8;
        let cipher: Vec<u8> = plain.iter().map(|&b| b ^ key).collect();
        let (recovered_key, decrypted) = XorDecryptor::recover_single_byte_key(&cipher);
        // Key 0x11 XOR 'A'(0x41) = 0x50 'P', key 0x11 XOR 'B'(0x42) = 0x53 'S'.
        // The recovered key maximises printable ASCII, so both should be printable.
        assert!(decrypted.iter().all(|&b| b.is_ascii_graphic() || b == b' '));
        let _ = recovered_key; // Value is heuristic; just verify no panic.
    }

    #[test]
    fn test_xor_entropy() {
        let uniform: Vec<u8> = (0..=255).collect();
        let entropy = XorDecryptor::entropy(&uniform);
        // Perfectly uniform → ~8.0 bits.
        assert!((entropy - 8.0).abs() < 0.01);

        let constant = vec![0xAA; 256];
        assert_eq!(XorDecryptor::entropy(&constant), 0.0);
    }

    // ── RolRorDecryptor ──────────────────────────────────────────────────────

    #[test]
    fn test_rol_ror_roundtrip() {
        for rot in 1u8..8 {
            for byte in 0u8..=255 {
                assert_eq!(
                    byte,
                    RolRorDecryptor::ror(RolRorDecryptor::rol(byte, rot), rot)
                );
                assert_eq!(
                    byte,
                    RolRorDecryptor::rol(RolRorDecryptor::ror(byte, rot), rot)
                );
            }
        }
    }

    #[test]
    fn test_decrypt_rol() {
        let data = vec![0x90u8, 0x48, 0x31];
        let encrypted: Vec<u8> = data.iter().map(|&b| RolRorDecryptor::rol(b, 3)).collect();
        let decrypted = RolRorDecryptor::decrypt_rol(&encrypted, 3);
        assert_eq!(decrypted, data);
    }

    #[test]
    fn test_decrypt_ror() {
        let data = vec![0x90u8, 0x48, 0x31];
        let encrypted: Vec<u8> = data.iter().map(|&b| RolRorDecryptor::ror(b, 5)).collect();
        let decrypted = RolRorDecryptor::decrypt_ror(&encrypted, 5);
        assert_eq!(decrypted, data);
    }

    // ── SimpleSubstitution ───────────────────────────────────────────────────

    #[test]
    fn test_most_frequent_byte() {
        let data = vec![0xAA, 0xAA, 0xAA, 0xBB, 0xCC];
        assert_eq!(SimpleSubstitution::most_frequent_byte(&data), 0xAA);
    }

    #[test]
    fn test_substitution_table_and_apply() {
        let data = vec![0x01, 0x01, 0x02];
        let table = SimpleSubstitution::build_substitution_table(&data, 0x00);
        // 0x01 (most frequent) → 0x00
        assert_eq!(table[0x01], 0x00);
        // Other bytes map to themselves.
        assert_eq!(table[0x02], 0x02);
        let out = SimpleSubstitution::apply_table(&data, &table);
        assert_eq!(out, vec![0x00, 0x00, 0x02]);
    }

    // ── Base64Decoder ────────────────────────────────────────────────────────

    #[test]
    fn test_base64_decode_basic() {
        // "Hello" → "SGVsbG8="
        let encoded = b"SGVsbG8=";
        let decoded = Base64Decoder::decode(encoded).unwrap();
        assert_eq!(decoded, b"Hello");
    }

    #[test]
    fn test_base64_decode_no_padding() {
        // "Man" → "TWFu"
        let decoded = Base64Decoder::decode(b"TWFu").unwrap();
        assert_eq!(decoded, b"Man");
    }

    #[test]
    fn test_base64_decode_invalid() {
        assert!(Base64Decoder::decode(b"$$$$$").is_none());
    }

    #[test]
    fn test_base64_find_all() {
        let mut data = b"prefix ".to_vec();
        data.extend_from_slice(b"SGVsbG8sV29ybGQh"); // "Hello,World!"
        data.extend_from_slice(b" suffix");
        let finds = Base64Decoder::find_all(&data);
        assert!(!finds.is_empty());
        assert_eq!(finds[0].decoded, b"Hello,World!");
    }

    // ── StringDecryptor ──────────────────────────────────────────────────────

    #[test]
    fn test_string_decrypt_xor_constant() {
        let plain = b"Hello World  padding!";
        let key = 0x13u8;
        let cipher: Vec<u8> = plain.iter().map(|&b| b ^ key).collect();
        let results = StringDecryptor::try_xor_constant(&cipher, 8);
        assert!(!results.is_empty());
        let best = results
            .iter()
            .max_by(|a, b| a.confidence.partial_cmp(&b.confidence).unwrap())
            .unwrap();
        assert!(best.plaintext.contains("Hello"));
    }

    #[test]
    fn test_string_decrypt_xor_rolling() {
        let plain = b"SecretMessage!!!!";
        let initial_key = 0x7Au8;
        let mut cipher = Vec::new();
        let mut prev = initial_key;
        for &b in plain {
            let c = b ^ prev;
            cipher.push(c);
            prev = c;
        }
        let results = StringDecryptor::try_xor_rolling(&cipher, 8);
        assert!(!results.is_empty());
    }

    // ── DeobfResult merge ────────────────────────────────────────────────────

    #[test]
    fn test_deobf_result_merge() {
        let mut r1 = DeobfResult::new(2, vec!["a".into()], 10, 0.8);
        let r2 = DeobfResult::new(2, vec!["b".into()], 5, 0.6);
        r1.merge(&r2);
        assert_eq!(r1.patches_applied, 4);
        assert_eq!(r1.transformations.len(), 2);
        assert_eq!(r1.modified_bytes, 15);
        assert!((r1.confidence - 0.7).abs() < 0.01);
    }

    // ── PassRegistry ────────────────────────────────────────────────────────

    #[test]
    fn test_registry_register_and_get() {
        let mut registry = PassRegistry::new();
        registry.register(Box::new(AlwaysNop));
        assert_eq!(registry.len(), 1);
        assert!(registry.get("nop").is_some());
        assert!(registry.get("missing").is_none());
    }

    #[test]
    fn test_registry_names_sorted() {
        let mut registry = PassRegistry::new();
        registry.register(Box::new(AlwaysNop));
        registry.register(Box::new(AlwaysErrors));
        let names = registry.names();
        assert_eq!(names, vec!["error", "nop"]);
    }

    #[test]
    fn test_registry_run_selection() {
        let mut registry = PassRegistry::new();
        registry.register(Box::new(AlwaysNop));
        let mut ctx = DeobfContext::new(vec![0]);
        let result = registry.run_selection(&["nop"], &mut ctx).unwrap();
        assert_eq!(result.pass_results.len(), 1);
    }

    #[test]
    fn test_registry_unknown_pass_errors() {
        let registry = PassRegistry::new();
        let mut ctx = DeobfContext::new(vec![]);
        let result = registry.run_selection(&["missing"], &mut ctx);
        assert!(result.is_err());
    }

    // ── TransformResult ──────────────────────────────────────────────────────

    #[test]
    fn test_transform_result_is_applied() {
        let r = TransformResult::Applied {
            rule: "r".into(),
            description: "d".into(),
        };
        assert!(r.is_applied());
        assert!(!r.is_skipped());
    }

    #[test]
    fn test_transform_result_is_skipped() {
        let r = TransformResult::Skipped {
            reason: "precondition not met".into(),
        };
        assert!(r.is_skipped());
        assert!(!r.is_applied());
    }

    #[test]
    fn test_transform_result_error() {
        let r = TransformResult::Error {
            message: "oops".into(),
        };
        assert!(!r.is_applied());
    }

    // ── DeobfReport ─────────────────────────────────────────────────────────

    #[test]
    fn test_deobf_report_from_pipeline() {
        let mut pipeline = PipelineResult::default();
        let r = DeobfResult::new(3, vec!["a".into()], 12, 0.9);
        pipeline.total = r.clone();
        pipeline.pass_results.push(("nop".into(), r));
        let report = DeobfReport::from_pipeline(pipeline);
        assert_eq!(report.total_patches, 3);
        assert_eq!(report.total_modified_bytes, 12);
        assert!((report.overall_confidence - 0.9).abs() < 0.01);
    }

    #[test]
    fn test_deobf_report_log_transform() {
        let mut report = DeobfReport::default();
        report.log_transform(TransformResult::Applied {
            rule: "xor-fold".into(),
            description: "folded xor".into(),
        });
        report.log_transform(TransformResult::Skipped {
            reason: "no match".into(),
        });
        assert_eq!(report.applied_count(), 1);
        assert_eq!(report.transform_log.len(), 2);
    }

    // ── Rc4Decryptor ────────────────────────────────────────────────────────

    #[test]
    fn test_rc4_encrypt_decrypt_roundtrip() {
        let plaintext = b"Hello, RC4 World!";
        let key = b"SecretKey";
        let ciphertext = Rc4Decryptor::decrypt(plaintext, key);
        let decrypted = Rc4Decryptor::decrypt(&ciphertext, key);
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_rc4_known_vector() {
        // RFC 6229 test vector: key=0x0102030405, plaintext=zeros (first 16 bytes).
        let key = [0x01u8, 0x02, 0x03, 0x04, 0x05];
        let plain = vec![0u8; 16];
        let cipher = Rc4Decryptor::decrypt(&plain, &key);
        // First output byte of this stream is 0xB2.
        assert_eq!(cipher[0], 0xB2);
    }

    #[test]
    fn test_rc4_empty_key_is_deterministic() {
        // RC4 with an empty key still produces a keystream (using a zero-length key in KSA).
        // Verify encrypt(encrypt(data, &[])) == data (XOR symmetry).
        let data = vec![0xAA, 0xBB, 0xCC];
        let encrypted = Rc4Decryptor::decrypt(&data, &[]);
        let roundtrip = Rc4Decryptor::decrypt(&encrypted, &[]);
        assert_eq!(roundtrip, data);
    }

    #[test]
    fn test_rc4_ksa_permutation() {
        let s = Rc4Decryptor::ksa(b"key");
        // S-box must be a permutation of 0..=255.
        let mut seen = [false; 256];
        for &b in &s {
            seen[b as usize] = true;
        }
        assert!(seen.iter().all(|&x| x));
    }

    // ── ChaCha20Decryptor ────────────────────────────────────────────────────

    #[test]
    fn test_chacha20_quarter_round_rfc_test_vector() {
        // RFC 8439 §2.1.1 test vector.
        let (a, b, c, d) =
            ChaCha20Decryptor::quarter_round(0x1111_1111, 0x0102_0304, 0x9b8d_6f43, 0x0123_4567);
        assert_eq!(a, 0xea2a_92f4);
        assert_eq!(b, 0xcb1c_f8ce);
        assert_eq!(c, 0x4581_472e);
        assert_eq!(d, 0x5881_c4bb);
    }

    #[test]
    fn test_chacha20_encrypt_decrypt_roundtrip() {
        let key = [0u8; 32];
        let nonce = [0u8; 12];
        let plain = b"ChaCha20 test payload 1234567890".to_vec();
        let cipher = ChaCha20Decryptor::crypt(&plain, &key, &nonce).unwrap();
        let decrypted = ChaCha20Decryptor::crypt(&cipher, &key, &nonce).unwrap();
        assert_eq!(decrypted, plain);
    }

    #[test]
    fn test_chacha20_keystream_not_all_zero() {
        let key = [0u8; 32];
        let nonce = [0u8; 12];
        let plain = vec![0u8; 64];
        let cipher = ChaCha20Decryptor::crypt(&plain, &key, &nonce).unwrap();
        assert!(cipher.iter().any(|&b| b != 0));
    }

    // ── Adler32 ──────────────────────────────────────────────────────────────

    #[test]
    fn test_adler32_known_vector() {
        // "Wikipedia" → 0x11E60398
        let val = Adler32::checksum(b"Wikipedia");
        assert_eq!(val, 0x11E6_0398);
    }

    #[test]
    fn test_adler32_empty() {
        assert_eq!(Adler32::checksum(&[]), 1); // a=1, b=0
    }

    // ── Crc32 ────────────────────────────────────────────────────────────────

    #[test]
    fn test_crc32_known_vector() {
        // "123456789" → 0xCBF43926
        let val = Crc32::checksum(b"123456789");
        assert_eq!(val, 0xCBF4_3926);
    }

    #[test]
    fn test_crc32_table_matches_bitwise() {
        let data = b"test data payload";
        assert_eq!(Crc32::checksum(data), Crc32::checksum_table(data));
    }

    // ── EntropyScanner ────────────────────────────────────────────────────────

    #[test]
    fn test_entropy_scanner_detects_high_entropy() {
        // Generate pseudo-random-looking data (all 256 bytes).
        let data: Vec<u8> = (0u8..=255).collect();
        let scanner = EntropyScanner::default();
        let regions = scanner.scan(&data);
        assert!(!regions.is_empty());
        assert!(regions[0].entropy > 7.0);
    }

    #[test]
    fn test_entropy_scanner_no_alert_on_zeros() {
        let data = vec![0u8; 512];
        let scanner = EntropyScanner::default();
        let regions = scanner.scan(&data);
        assert!(regions.is_empty());
    }

    #[test]
    fn test_entropy_scanner_max_region() {
        let data: Vec<u8> = (0u8..=255).cycle().take(512).collect();
        let scanner = EntropyScanner::default();
        let max = scanner.max_entropy_region(&data);
        assert!(max.is_some());
    }

    // ── BinarySection ─────────────────────────────────────────────────────────

    #[test]
    fn test_section_looks_packed() {
        let data: Vec<u8> = (0u8..=255).collect();
        let section = BinarySection::new(".packed", 0x1000, data);
        assert!(section.looks_packed());
    }

    #[test]
    fn test_section_not_packed_zeros() {
        let section = BinarySection::new(".bss", 0x2000, vec![0u8; 64]);
        assert!(!section.looks_packed());
        assert_eq!(section.len(), 64);
    }

    // ── PatchSet ──────────────────────────────────────────────────────────────

    #[test]
    fn test_patchset_insert_non_overlapping() {
        let mut ps = PatchSet::new();
        let p1 = Patch::new(0, vec![], vec![0x90, 0x90], "a");
        let p2 = Patch::new(4, vec![], vec![0x90, 0x90], "b");
        assert!(ps.insert(p1));
        assert!(ps.insert(p2));
        assert_eq!(ps.len(), 2);
    }

    #[test]
    fn test_patchset_rejects_overlapping() {
        let mut ps = PatchSet::new();
        let p1 = Patch::new(0, vec![], vec![0x90, 0x90, 0x90], "a");
        let p2 = Patch::new(2, vec![], vec![0x90, 0x90], "b");
        assert!(ps.insert(p1));
        assert!(!ps.insert(p2)); // Overlaps.
    }

    #[test]
    fn test_patchset_apply_to() {
        let mut ps = PatchSet::new();
        ps.insert(Patch::new(1, vec![], vec![0xFF], "mark"));
        let data = vec![0x00, 0x00, 0x00];
        let out = ps.apply_to(&data).unwrap();
        assert_eq!(out, vec![0x00, 0xFF, 0x00]);
    }

    #[test]
    fn test_patchset_is_sorted() {
        let mut ps = PatchSet::new();
        ps.insert(Patch::new(10, vec![], vec![0xAA], "b"));
        ps.insert(Patch::new(0, vec![], vec![0xBB], "a"));
        let patches = ps.patches();
        assert_eq!(patches[0].offset, 0);
        assert_eq!(patches[1].offset, 10);
    }

    // ── HexDumper ─────────────────────────────────────────────────────────────

    #[test]
    fn test_hexdumper_basic() {
        let dumper = HexDumper::new();
        let data = b"Hello, World!";
        let out = dumper.dump(data);
        assert!(out.contains("48")); // 'H'
        assert!(out.contains("Hello"));
    }

    #[test]
    fn test_hexdumper_hex_only() {
        let dumper = HexDumper::new();
        let out = dumper.hex_only(&[0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(out, "de ad be ef");
    }

    #[test]
    fn test_hexdumper_base_address() {
        let dumper = HexDumper::new().with_base(0x4000_0000);
        let out = dumper.dump(&[0u8; 1]);
        assert!(out.contains("40000000"));
    }

    // ── ConstantFoldingPass ───────────────────────────────────────────────────

    #[test]
    fn test_constant_folding_add() {
        // Encode ADD(5, 7) = [0x01, 5, 0, 0, 0, 7, 0, 0, 0]
        let mut data = vec![0x01, 5, 0, 0, 0, 7, 0, 0, 0];
        data.extend_from_slice(&[0x90u8; 1]); // Padding to satisfy is_applicable.
        let mut ctx = DeobfContext::new(data);
        let pass = ConstantFoldingPass::new();
        let result = pass.run(&mut ctx).unwrap();
        assert_eq!(result.patches_applied, 1);
        let patched = ctx.apply_patches().unwrap();
        // Patched: op=ADD, result=12, second=0.
        let result_val = u32::from_le_bytes([patched[1], patched[2], patched[3], patched[4]]);
        assert_eq!(result_val, 12);
    }

    #[test]
    fn test_constant_folding_xor() {
        let data = vec![0x05, 0xFF, 0, 0, 0, 0xFF, 0, 0, 0, 0x90];
        let mut ctx = DeobfContext::new(data);
        let pass = ConstantFoldingPass::new();
        let result = pass.run(&mut ctx).unwrap();
        assert!(result.patches_applied > 0);
        let patched = ctx.apply_patches().unwrap();
        let result_val = u32::from_le_bytes([patched[1], patched[2], patched[3], patched[4]]);
        assert_eq!(result_val, 0); // 0xFF ^ 0xFF = 0
    }

    // ── NopSledRemover ────────────────────────────────────────────────────────

    #[test]
    fn test_nop_sled_remover_finds_sleds() {
        let remover = NopSledRemover::new();
        let data = vec![0xCC, 0x90, 0x90, 0x90, 0x90, 0x90, 0xCC];
        let sleds = remover.find_sleds(&data);
        assert_eq!(sleds.len(), 1);
        assert_eq!(sleds[0].0, 1);
        assert_eq!(sleds[0].1, 5);
    }

    #[test]
    fn test_nop_sled_remover_pass() {
        let data = vec![0x90u8; 8];
        let mut ctx = DeobfContext::new(data);
        let pass = NopSledRemover::new();
        assert!(pass.is_applicable(&ctx));
        let result = pass.run(&mut ctx).unwrap();
        assert_eq!(result.patches_applied, 1);
        assert_eq!(result.modified_bytes, 8);
    }

    #[test]
    fn test_nop_sled_remover_min_sled() {
        let remover = NopSledRemover::with_min_sled(8);
        let data = vec![0x90u8; 4]; // Shorter than min_sled.
        let sleds = remover.find_sleds(&data);
        assert!(sleds.is_empty());
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DeobfOptions
// ─────────────────────────────────────────────────────────────────────────────

/// Configuration options for a deobfuscation pipeline run.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct DeobfOptions {
    /// Maximum number of iterations for iterative passes.
    pub max_iterations: usize,
    /// Apply aggressive (potentially lossy) simplifications.
    pub aggressive: bool,
    /// Log verbose information for debugging.
    pub verbose: bool,
    /// Binary architecture hint (e.g. "`x86_64`").
    pub arch_hint: Option<String>,
}

/// Result of running an entire pipeline.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DeobfPipelineResult {
    pub total_patches: usize,
    pub passes_run: usize,
    pub elapsed_ms: u64,
    pub pass_results: Vec<(String, DeobfResult)>,
}

impl DeobfPipelineResult {
    #[must_use]
    pub const fn success_rate(&self) -> f64 {
        if self.passes_run == 0 { 0.0 } else { 1.0 }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DeobfPassRegistry
// ─────────────────────────────────────────────────────────────────────────────

/// Registry of named deobfuscation passes.
#[derive(Default)]
pub struct DeobfPassRegistry {
    passes: HashMap<String, std::sync::Arc<dyn DeobfPass>>,
}

impl DeobfPassRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self, pass: std::sync::Arc<dyn DeobfPass>) {
        self.passes.insert(pass.name().to_string(), pass);
    }

    #[must_use]
    pub fn get(&self, name: &str) -> Option<std::sync::Arc<dyn DeobfPass>> {
        if let Some(p) = self.passes.get(name).cloned() {
            return Some(p);
        }
        // Fall back to normalizing separators ('_' <-> '-') so callers can
        // refer to passes using either snake_case or kebab-case.
        let alt_hyphen = name.replace('_', "-");
        if let Some(p) = self.passes.get(&alt_hyphen).cloned() {
            return Some(p);
        }
        let alt_under = name.replace('-', "_");
        self.passes.get(&alt_under).cloned()
    }

    #[must_use]
    pub fn count(&self) -> usize {
        self.passes.len()
    }

    #[must_use]
    pub fn names(&self) -> Vec<&str> {
        self.passes.keys().map(String::as_str).collect()
    }

    /// Build a pipeline from pass names in order.
    #[must_use] 
    pub fn build_pipeline(&self, pass_names: &[&str], _options: DeobfOptions) -> DeobfPipeline {
        let mut pipeline = DeobfPipeline::new();
        for name in pass_names {
            if let Some(pass) = self.get(name) {
                pipeline.add_pass_arc(pass);
            }
        }
        pipeline
    }
}

impl std::fmt::Debug for DeobfPassRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "DeobfPassRegistry {{ {} passes }}", self.passes.len())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DeobfSession
// ─────────────────────────────────────────────────────────────────────────────

/// A deobfuscation session over a single binary.
#[derive(Debug)]
pub struct DeobfSession {
    pub id: String,
    pub binary_path: Option<String>,
    pub pipeline: DeobfPipeline,
    pub results: Vec<DeobfPipelineResult>,
    pub metrics: DeobfMetrics,
}

impl DeobfSession {
    #[must_use]
    pub fn new(id: impl Into<String>, pipeline: DeobfPipeline) -> Self {
        Self {
            id: id.into(),
            binary_path: None,
            pipeline,
            results: Vec::new(),
            metrics: DeobfMetrics::default(),
        }
    }

    /// # Errors
    /// Returns [`DeobfError`] if the pipeline fails.
    pub fn run_on(&mut self, ctx: &mut DeobfContext) -> Result<(), DeobfError> {
        let result = self.pipeline.run(ctx)?;
        self.metrics.total_patches += result.total_patches as u64;
        self.metrics.passes_run += result.passes_run as u64;
        self.results.push(result);
        Ok(())
    }

    #[must_use]
    pub const fn run_count(&self) -> usize {
        self.results.len()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DeobfMetrics
// ─────────────────────────────────────────────────────────────────────────────

/// Accumulated metrics across a deobfuscation session.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct DeobfMetrics {
    pub total_patches: u64,
    pub passes_run: u64,
    pub bytes_modified: u64,
    pub functions_processed: u64,
    pub time_ms: u64,
}

impl DeobfMetrics {
    #[must_use]
    pub fn patches_per_pass(&self) -> f64 {
        if self.passes_run == 0 {
            0.0
        } else {
            u64_to_f64(self.total_patches) / u64_to_f64(self.passes_run)
        }
    }
}

impl std::fmt::Display for DeobfMetrics {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "patches={} passes={} bytes={} funcs={} ms={}",
            self.total_patches,
            self.passes_run,
            self.bytes_modified,
            self.functions_processed,
            self.time_ms
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// HybridDeobf — runs multiple pipelines and merges results
// ─────────────────────────────────────────────────────────────────────────────

/// Runs multiple pipelines and takes the best result.
pub struct HybridDeobf {
    pipelines: Vec<DeobfPipeline>,
}

impl HybridDeobf {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            pipelines: Vec::new(),
        }
    }

    pub fn add_pipeline(&mut self, p: DeobfPipeline) {
        self.pipelines.push(p);
    }

    /// # Errors
    /// Returns [`DeobfError`] if any pipeline fails.
    pub fn run(&self, data: &[u8]) -> Result<Vec<u8>, DeobfError> {
        let mut best_data = data.to_vec();
        let mut best_patches = 0;

        for pipeline in &self.pipelines {
            let mut ctx = DeobfContext::new(data.to_vec());
            let result = pipeline.run(&mut ctx)?;
            if result.total_patches >= best_patches {
                best_patches = result.total_patches;
                best_data = ctx.apply_patches()?;
            }
        }
        Ok(best_data)
    }

    #[must_use]
    pub const fn pipeline_count(&self) -> usize {
        self.pipelines.len()
    }
}

impl Default for HybridDeobf {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for HybridDeobf {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "HybridDeobf {{ pipelines: {} }}", self.pipelines.len())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DeobfHeuristics
// ─────────────────────────────────────────────────────────────────────────────

/// Heuristics for deciding which passes to run.
#[derive(Debug, Default)]
pub struct DeobfHeuristics {
    entropy_threshold: f64,
    known_signatures: Vec<String>,
}

impl DeobfHeuristics {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            entropy_threshold: 7.0,
            known_signatures: Vec::new(),
        }
    }

    pub fn add_signature(&mut self, sig: impl Into<String>) {
        self.known_signatures.push(sig.into());
    }

    /// Compute byte entropy of a slice.
    #[must_use]
    pub fn entropy(data: &[u8]) -> f64 {
        if data.is_empty() {
            return 0.0;
        }
        let mut freq = [0u32; 256];
        for &b in data {
            freq[b as usize] += 1;
        }
        let len = usize_to_f64(data.len());
        freq.iter()
            .filter(|&&c| c > 0)
            .map(|&c| {
                let p = f64::from(c) / len;
                -p * p.log2()
            })
            .sum()
    }

    /// Detect if data looks obfuscated (high entropy).
    #[must_use]
    pub fn is_likely_obfuscated(&self, data: &[u8]) -> bool {
        Self::entropy(data) > self.entropy_threshold
    }

    #[must_use]
    pub const fn signature_count(&self) -> usize {
        self.known_signatures.len()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ObfuscationClassifier
// ─────────────────────────────────────────────────────────────────────────────

/// Classifies what type of obfuscation is present.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ObfuscationType {
    ControlFlowFlattening,
    VirtualMachine,
    SelfModifyingCode,
    StringEncryption,
    OpaquePredicates,
    MixedBooleanArithmetic,
    AntiDebug,
    PackedExecutable,
    Unknown,
}

impl std::fmt::Display for ObfuscationType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ControlFlowFlattening => write!(f, "CFF"),
            Self::VirtualMachine => write!(f, "VM"),
            Self::SelfModifyingCode => write!(f, "SMC"),
            Self::StringEncryption => write!(f, "StringEnc"),
            Self::OpaquePredicates => write!(f, "Opaque"),
            Self::MixedBooleanArithmetic => write!(f, "MBA"),
            Self::AntiDebug => write!(f, "AntiDebug"),
            Self::PackedExecutable => write!(f, "Packed"),
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}

/// Detects which obfuscation techniques are present.
#[derive(Debug, Default)]
pub struct ObfuscationClassifier {
    detected: Vec<(ObfuscationType, f64)>, // (type, confidence)
}

impl ObfuscationClassifier {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn classify(&mut self, data: &[u8]) {
        // High entropy → packed or encrypted.
        let entropy = DeobfHeuristics::entropy(data);
        if entropy > 7.5 {
            self.detected
                .push((ObfuscationType::PackedExecutable, entropy / 8.0));
        }

        // Look for CFF signature: many indirect branches.
        let jmp_count = data.windows(1).filter(|w| w[0] == 0xFF).count();
        if usize_to_f64(jmp_count) / usize_to_f64(data.len()) > 0.02 {
            self.detected
                .push((ObfuscationType::ControlFlowFlattening, 0.6));
        }

        // IsDebuggerPresent → anti-debug.
        let idp_pattern = b"\x64\x8B\x0D";
        if data.windows(idp_pattern.len()).any(|w| w == idp_pattern) {
            self.detected.push((ObfuscationType::AntiDebug, 0.9));
        }
    }

    #[must_use]
    pub fn detections(&self) -> &[(ObfuscationType, f64)] {
        &self.detected
    }

    #[must_use]
    pub fn most_likely(&self) -> Option<ObfuscationType> {
        self.detected
            .iter()
            .max_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal))
            .map(|(t, _)| *t)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DeobfDb — in-memory persistence
// ─────────────────────────────────────────────────────────────────────────────

/// Stores deobfuscation results for later retrieval.
#[derive(Debug, Default)]
pub struct DeobfDb {
    patches: HashMap<String, Vec<Patch>>,
    reports: Vec<DeobfReport>,
}

impl DeobfDb {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn save_patches(&mut self, binary_id: impl Into<String>, patches: Vec<Patch>) {
        self.patches.insert(binary_id.into(), patches);
    }

    pub fn save_report(&mut self, report: DeobfReport) {
        self.reports.push(report);
    }

    #[must_use]
    pub fn patches_for(&self, binary_id: &str) -> &[Patch] {
        self.patches
            .get(binary_id)
            .map_or(&[], Vec::as_slice)
    }

    #[must_use]
    pub const fn report_count(&self) -> usize {
        self.reports.len()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// IterativeDeobf
// ─────────────────────────────────────────────────────────────────────────────

/// Runs a pipeline iteratively until convergence.
#[derive(Debug)]
pub struct IterativeDeobf {
    pipeline: DeobfPipeline,
    max_iterations: usize,
}

impl IterativeDeobf {
    #[must_use]
    pub const fn new(pipeline: DeobfPipeline, max_iterations: usize) -> Self {
        Self {
            pipeline,
            max_iterations,
        }
    }

    /// # Errors
    /// Returns [`DeobfError`] if the pipeline fails during any iteration.
    pub fn run(&self, data: Vec<u8>) -> Result<(Vec<u8>, usize), DeobfError> {
        let mut current = data;
        let mut iterations = 0;

        loop {
            let mut ctx = DeobfContext::new(current.clone());
            let result = self.pipeline.run(&mut ctx)?;
            iterations += 1;

            if result.total_patches == 0 || iterations >= self.max_iterations {
                let final_data = ctx.apply_patches()?;
                return Ok((final_data, iterations));
            }
            current = ctx.apply_patches()?;
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Additional tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod extended_deobf_tests {
    use super::*;

    // ── DeobfPassRegistry ─────────────────────────────────────────────────────

    #[test]
    fn test_pass_registry_register_and_get() {
        let mut reg = DeobfPassRegistry::new();
        reg.register(std::sync::Arc::new(NopSledRemover::new()));
        assert_eq!(reg.count(), 1);
        assert!(reg.get("nop_sled_remover").is_some());
    }

    #[test]
    fn test_pass_registry_build_pipeline() {
        let mut reg = DeobfPassRegistry::new();
        reg.register(std::sync::Arc::new(NopSledRemover::new()));
        let pipeline = reg.build_pipeline(&["nop_sled_remover"], DeobfOptions::default());
        assert_eq!(pipeline.pass_count(), 1);
    }

    // ── DeobfPipeline ─────────────────────────────────────────────────────────

    #[test]
    fn test_pipeline_runs_pass() {
        let mut pipeline = DeobfPipeline::with_options(DeobfOptions::default());
        pipeline.add_pass_arc(std::sync::Arc::new(NopSledRemover::new()));
        let mut ctx = DeobfContext::new(vec![0x90u8; 8]);
        let result = pipeline.run(&mut ctx).unwrap();
        assert_eq!(result.passes_run, 1);
        assert!(result.total_patches > 0);
    }

    // ── DeobfMetrics ─────────────────────────────────────────────────────────

    #[test]
    fn test_deobf_metrics_patches_per_pass() {
        let m = DeobfMetrics {
            total_patches: 10,
            passes_run: 5,
            ..Default::default()
        };
        assert!((m.patches_per_pass() - 2.0).abs() < 1e-9);
    }

    #[test]
    fn test_deobf_metrics_display() {
        let m = DeobfMetrics {
            total_patches: 3,
            passes_run: 2,
            bytes_modified: 6,
            functions_processed: 1,
            time_ms: 100,
        };
        assert!(m.to_string().contains("patches=3"));
    }

    // ── HybridDeobf ───────────────────────────────────────────────────────────

    #[test]
    fn test_hybrid_deobf_run() {
        let mut hd = HybridDeobf::new();
        let mut p1 = DeobfPipeline::with_options(DeobfOptions::default());
        p1.add_pass_arc(std::sync::Arc::new(NopSledRemover::new()));
        hd.add_pipeline(p1);
        let data = vec![0x90u8; 8];
        let result = hd.run(&data).unwrap();
        // NOP sled replaced with 0x00.
        assert_eq!(result.len(), 8);
    }

    // ── DeobfHeuristics ───────────────────────────────────────────────────────

    #[test]
    fn test_entropy_uniform() {
        let data: Vec<u8> = (0..=255u8).collect();
        let e = DeobfHeuristics::entropy(&data);
        assert!((e - 8.0).abs() < 0.1);
    }

    #[test]
    fn test_entropy_constant() {
        let data = vec![0u8; 256];
        let e = DeobfHeuristics::entropy(&data);
        assert_eq!(e, 0.0);
    }

    #[test]
    fn test_is_likely_obfuscated_high_entropy() {
        let h = DeobfHeuristics::new();
        let data: Vec<u8> = (0..=255u8).cycle().take(1024).collect();
        // Uniform random data should have high entropy.
        assert!(h.is_likely_obfuscated(&data));
    }

    // ── ObfuscationClassifier ─────────────────────────────────────────────────

    #[test]
    fn test_classifier_uniform_data() {
        let mut clf = ObfuscationClassifier::new();
        let data: Vec<u8> = (0..=255u8).cycle().take(1024).collect();
        clf.classify(&data);
        assert!(!clf.detections().is_empty());
    }

    #[test]
    fn test_obfuscation_type_display() {
        assert_eq!(ObfuscationType::ControlFlowFlattening.to_string(), "CFF");
        assert_eq!(ObfuscationType::VirtualMachine.to_string(), "VM");
        assert_eq!(ObfuscationType::PackedExecutable.to_string(), "Packed");
    }

    // ── DeobfReport ───────────────────────────────────────────────────────────

    #[test]
    fn test_deobf_report_finalize() {
        let mut r = DeobfReport::new("test.exe");
        r.add_obfuscation(ObfuscationType::AntiDebug, 0.9);
        r.total_patches = 5;
        r.finalize();
        assert!(!r.summary().is_empty());
        assert!(r.to_string().contains("technique"));
    }

    // ── DeobfDb ───────────────────────────────────────────────────────────────

    #[test]
    fn test_deobf_db_save_load() {
        let mut db = DeobfDb::new();
        db.save_patches(
            "binary1",
            vec![Patch {
                offset: 0,
                original: vec![0x90],
                patched: vec![0x00],
                reason: "nop".to_string(),
            }],
        );
        assert_eq!(db.patches_for("binary1").len(), 1);
        assert_eq!(db.patches_for("nonexistent").len(), 0);
    }

    #[test]
    fn test_deobf_db_report() {
        let mut db = DeobfDb::new();
        db.save_report(DeobfReport::new("test.exe"));
        assert_eq!(db.report_count(), 1);
    }

    // ── IterativeDeobf ────────────────────────────────────────────────────────

    #[test]
    fn test_iterative_deobf_converges() {
        let mut pipeline = DeobfPipeline::with_options(DeobfOptions::default());
        pipeline.add_pass_arc(std::sync::Arc::new(NopSledRemover::new()));
        let iter = IterativeDeobf::new(pipeline, 10);
        let data = vec![0x90u8; 8];
        let (result, iters) = iter.run(data).unwrap();
        assert_eq!(result.len(), 8);
        assert!(iters <= 10);
    }

    // ── DeobfSession ─────────────────────────────────────────────────────────

    #[test]
    fn test_deobf_session_run() {
        let pipeline = DeobfPipeline::with_options(DeobfOptions::default());
        let mut session = DeobfSession::new("session_1", pipeline);
        let mut ctx = DeobfContext::new(vec![0x90u8; 4]);
        session.run_on(&mut ctx).unwrap();
        assert_eq!(session.run_count(), 1);
    }
}
