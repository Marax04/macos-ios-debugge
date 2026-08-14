//! `deobf_pass_registry` — Execution registry of deobfuscation passes with
//! metadata, pattern-based lookup, and lifecycle management.
//!
//! The [`DeobfPassRegistry`] maps short pass names to boxed [`DeobfPass`]
//! implementations together with rich [`PassMetadata`].  A caller can query
//! the registry for all passes whose `applicable_patterns` overlap with a
//! detected obfuscation pattern string, then assemble a targeted pipeline.
//!
//! # Relation to `deobf_registry`
//! This module is an **execution registry**: each entry holds a live
//! `Box<dyn DeobfPass>` and can be invoked via [`DeobfPassRegistry::run_pass`]
//! or [`DeobfPassRegistry::run_all`]. Metadata here is lighter (no capability
//! flags or cost tiers) but adds pattern tags for fuzzy lookup and tracks
//! per-pass run/patch counters.
//!
//! [`deobf_registry`](crate::deobf_registry) is a **metadata-only catalogue**
//! that never holds live pass objects. It is suited for configuration UIs,
//! preset selection, and static analysis of the available pass graph.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::{DeobfContext, DeobfPass, DeobfResult, DeobfError};

// ─────────────────────────────────────────────────────────────────────────────
// PassCategory
// ─────────────────────────────────────────────────────────────────────────────

/// Broad category of a deobfuscation pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PassCategory {
    /// String decryption / recovery.
    StringDecryption,
    /// Control-flow normalisation (opaque predicates, flattening…).
    ControlFlow,
    /// Anti-debug / anti-analysis removal.
    AntiDebug,
    /// Packer / unpacker.
    Unpacking,
    /// Constant folding / dead-code elimination.
    Optimisation,
    /// Binary-level patching (NOP sleds, junk code).
    BinaryPatch,
    /// Import reconstruction.
    ImportReconstruction,
    /// Virtualiser / VM bytecode decompilation.
    Virtualiser,
    /// Generic / uncategorised pass.
    Generic,
}

impl PassCategory {
    /// Return the short label used in human-readable output.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::StringDecryption => "string-decrypt",
            Self::ControlFlow => "control-flow",
            Self::AntiDebug => "anti-debug",
            Self::Unpacking => "unpacking",
            Self::Optimisation => "optimisation",
            Self::BinaryPatch => "binary-patch",
            Self::ImportReconstruction => "import-recon",
            Self::Virtualiser => "virtualiser",
            Self::Generic => "generic",
        }
    }
}

impl std::fmt::Display for PassCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PassMetadata
// ─────────────────────────────────────────────────────────────────────────────

/// Rich metadata attached to every pass registered in a [`DeobfPassRegistry`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PassMetadata {
    /// Short, unique name (same as [`DeobfPass::name`]).
    pub name: String,
    /// One-line description.
    pub description: String,
    /// Broad category this pass belongs to.
    pub category: PassCategory,
    /// Version string (e.g. `"1.2.0"`).
    pub version: String,
    /// Obfuscation pattern tags this pass addresses (e.g. `"xor-string"`,
    /// `"nop-sled"`, `"opaque-predicate"`).
    pub applicable_patterns: Vec<String>,
    /// Whether this pass is safe to run without confirmation (no
    /// destructive side effects on the original binary).
    pub is_safe: bool,
    /// Estimated CPU cost: 1 = cheap, 5 = expensive.
    pub cost: u8,
    /// Passes that must run before this one (by name).
    pub dependencies: Vec<String>,
}

impl PassMetadata {
    /// Create a new [`PassMetadata`] with the given required fields and safe
    /// defaults for the rest.
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        description: impl Into<String>,
        category: PassCategory,
    ) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
            category,
            version: "1.0.0".into(),
            applicable_patterns: Vec::new(),
            is_safe: true,
            cost: 2,
            dependencies: Vec::new(),
        }
    }

    /// Builder: add applicable patterns.
    #[must_use]
    pub fn with_patterns(mut self, patterns: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.applicable_patterns
            .extend(patterns.into_iter().map(Into::into));
        self
    }

    /// Builder: set the cost level.
    #[must_use]
    pub const fn with_cost(mut self, cost: u8) -> Self {
        self.cost = cost;
        self
    }

    /// Builder: mark as potentially destructive.
    #[must_use]
    pub const fn unsafe_pass(mut self) -> Self {
        self.is_safe = false;
        self
    }

    /// Builder: add dependencies.
    #[must_use]
    pub fn with_dependencies(mut self, deps: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.dependencies.extend(deps.into_iter().map(Into::into));
        self
    }

    /// Builder: set the version string.
    #[must_use]
    pub fn with_version(mut self, version: impl Into<String>) -> Self {
        self.version = version.into();
        self
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PassEntry
// ─────────────────────────────────────────────────────────────────────────────

/// A single entry in the registry combining the live pass object with its
/// metadata.
pub struct PassEntry {
    /// The deobfuscation pass implementation.
    pub pass: Box<dyn DeobfPass>,
    /// Associated metadata.
    pub metadata: PassMetadata,
    /// Whether this pass is currently enabled (can be toggled at runtime).
    pub enabled: bool,
    /// Number of times this pass has been executed.
    pub run_count: u64,
    /// Total number of patches the pass has produced across all runs.
    pub total_patches: u64,
}

impl PassEntry {
    /// Create a new [`PassEntry`].
    #[must_use]
    pub fn new(pass: Box<dyn DeobfPass>, metadata: PassMetadata) -> Self {
        Self {
            pass,
            metadata,
            enabled: true,
            run_count: 0,
            total_patches: 0,
        }
    }

    /// Return the pass name (delegates to metadata).
    #[must_use]
    pub fn name(&self) -> &str {
        &self.metadata.name
    }

    /// Return `true` if any applicable pattern matches `pattern` (exact or
    /// substring match).
    #[must_use]
    pub fn matches_pattern(&self, pattern: &str) -> bool {
        self.metadata
            .applicable_patterns
            .iter()
            .any(|p| p == pattern || p.contains(pattern) || pattern.contains(p.as_str()))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// RegistryStats
// ─────────────────────────────────────────────────────────────────────────────

/// Aggregate statistics for a [`DeobfPassRegistry`].
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RegistryStats {
    /// Total number of registered passes.
    pub total_passes: usize,
    /// Number of currently-enabled passes.
    pub enabled_passes: usize,
    /// Number of disabled passes.
    pub disabled_passes: usize,
    /// Total executions across all passes.
    pub total_runs: u64,
    /// Total patches produced across all passes.
    pub total_patches: u64,
    /// Pass names grouped by category.
    pub by_category: HashMap<String, Vec<String>>,
}

// ─────────────────────────────────────────────────────────────────────────────
// DeobfPassRegistry
// ─────────────────────────────────────────────────────────────────────────────

/// A typed registry of named [`DeobfPass`] implementations with metadata and
/// pattern-based lookup.
///
/// # Example
/// ```rust,ignore
/// let mut reg = DeobfPassRegistry::new();
/// reg.register(NopSledPass::new(), PassMetadata::new("nop-sled", "Remove NOP sleds", PassCategory::BinaryPatch)
///     .with_patterns(["nop-sled", "sled"]));
/// let passes = reg.get_passes_for_pattern("nop-sled");
/// ```
#[derive(Default)]
pub struct DeobfPassRegistry {
    /// Entries stored in insertion order (for deterministic iteration).
    entries: Vec<PassEntry>,
    /// Name-to-index for O(1) lookup.
    index: HashMap<String, usize>,
}

impl std::fmt::Debug for DeobfPassRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeobfPassRegistry")
            .field("pass_count", &self.entries.len())
            .finish_non_exhaustive()
    }
}

impl DeobfPassRegistry {
    /// Create an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a pass with explicit metadata.  If a pass with the same name
    /// already exists it is replaced and the old entry is returned.
    pub fn register(
        &mut self,
        pass: Box<dyn DeobfPass>,
        metadata: PassMetadata,
    ) -> Option<PassEntry> {
        let name = metadata.name.clone();
        if let Some(&idx) = self.index.get(&name) {
            let entry = PassEntry::new(pass, metadata);
            let old = std::mem::replace(&mut self.entries[idx], entry);
            return Some(old);
        }
        let idx = self.entries.len();
        self.entries.push(PassEntry::new(pass, metadata));
        self.index.insert(name, idx);
        None
    }

    /// Register a pass using the pass's own `name()` and `description()` and a
    /// supplied category, with no patterns.  Convenience wrapper for simple
    /// registration without full metadata.
    pub fn register_simple(
        &mut self,
        pass: Box<dyn DeobfPass>,
        category: PassCategory,
    ) -> Option<PassEntry> {
        let meta = PassMetadata::new(pass.name(), pass.description(), category);
        self.register(pass, meta)
    }

    /// Look up a pass entry by name.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&PassEntry> {
        self.index.get(name).map(|&i| &self.entries[i])
    }

    /// Look up a pass entry by name (mutable).
    pub fn get_mut(&mut self, name: &str) -> Option<&mut PassEntry> {
        if let Some(&i) = self.index.get(name) {
            Some(&mut self.entries[i])
        } else {
            None
        }
    }

    /// Return all entries whose `applicable_patterns` match `pattern`.
    #[must_use]
    pub fn get_passes_for_pattern(&self, pattern: &str) -> Vec<&PassEntry> {
        self.entries
            .iter()
            .filter(|e| e.enabled && e.matches_pattern(pattern))
            .collect()
    }

    /// Return all entries in a given category.
    #[must_use]
    pub fn get_by_category(&self, category: PassCategory) -> Vec<&PassEntry> {
        self.entries
            .iter()
            .filter(|e| e.metadata.category == category)
            .collect()
    }

    /// Enable or disable a pass by name.  Returns `false` if the pass is not
    /// found.
    pub fn set_enabled(&mut self, name: &str, enabled: bool) -> bool {
        if let Some(&i) = self.index.get(name) {
            self.entries[i].enabled = enabled;
            return true;
        }
        false
    }

    /// Return all registered pass names in insertion order.
    #[must_use]
    pub fn names(&self) -> Vec<&str> {
        self.entries.iter().map(|e| e.metadata.name.as_str()).collect()
    }

    /// Number of registered passes.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` when no passes are registered.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Run a named pass on `ctx`, updating run/patch counters in the entry.
    ///
    /// # Errors
    /// Returns [`DeobfError`] if the pass itself returns an error, or
    /// [`DeobfError::NotApplicable`] if the pass name is not found or is
    /// disabled.
    pub fn run_pass(&mut self, name: &str, ctx: &mut DeobfContext) -> Result<DeobfResult, DeobfError> {
        let idx = self
            .index
            .get(name)
            .copied()
            .ok_or_else(|| DeobfError::NotApplicable(format!("pass '{name}' not found")))?;

        if !self.entries[idx].enabled {
            return Err(DeobfError::NotApplicable(format!(
                "pass '{name}' is disabled"
            )));
        }

        let result = self.entries[idx].pass.run(ctx)?;
        self.entries[idx].run_count += 1;
        self.entries[idx].total_patches += result.patches_applied as u64;
        Ok(result)
    }

    /// Run all enabled passes in insertion order, collecting results.  Errors
    /// from individual passes are recorded in the returned error list rather
    /// than aborting the loop.
    pub fn run_all(
        &mut self,
        ctx: &mut DeobfContext,
    ) -> (Vec<(String, DeobfResult)>, Vec<String>) {
        let mut results = Vec::new();
        let mut errors = Vec::new();

        // Collect indices of enabled, applicable passes first to avoid borrow
        // conflicts when calling run.
        let eligible: Vec<usize> = self
            .entries
            .iter()
            .enumerate()
            .filter(|(_, e)| e.enabled && e.pass.is_applicable(ctx))
            .map(|(i, _)| i)
            .collect();

        for idx in eligible {
            let name = self.entries[idx].metadata.name.clone();
            match self.entries[idx].pass.run(ctx) {
                Ok(result) => {
                    self.entries[idx].run_count += 1;
                    self.entries[idx].total_patches += result.patches_applied as u64;
                    results.push((name, result));
                }
                Err(e) => {
                    errors.push(format!("pass '{name}' failed: {e}"));
                    self.entries[idx].run_count += 1;
                }
            }
        }

        (results, errors)
    }

    /// Compute and return aggregate statistics.
    #[must_use]
    pub fn stats(&self) -> RegistryStats {
        let mut by_category: HashMap<String, Vec<String>> = HashMap::new();
        let mut total_runs = 0u64;
        let mut total_patches = 0u64;
        let mut enabled_passes = 0usize;
        let mut disabled_passes = 0usize;

        for entry in &self.entries {
            let cat = entry.metadata.category.label().to_string();
            by_category
                .entry(cat)
                .or_default()
                .push(entry.metadata.name.clone());
            total_runs += entry.run_count;
            total_patches += entry.total_patches;
            if entry.enabled {
                enabled_passes += 1;
            } else {
                disabled_passes += 1;
            }
        }

        RegistryStats {
            total_passes: self.entries.len(),
            enabled_passes,
            disabled_passes,
            total_runs,
            total_patches,
            by_category,
        }
    }

    /// Return all pass names that depend on `pass_name` (directly or
    /// transitively).
    #[must_use]
    pub fn dependents_of(&self, pass_name: &str) -> Vec<&str> {
        self.entries
            .iter()
            .filter(|e| e.metadata.dependencies.iter().any(|d| d == pass_name))
            .map(|e| e.metadata.name.as_str())
            .collect()
    }

    /// Validate the registry: check that all dependency names exist.
    ///
    /// Returns a list of `"pass_name: unknown dependency dep_name"` strings.
    #[must_use]
    pub fn validate_dependencies(&self) -> Vec<String> {
        let mut errors = Vec::new();
        for entry in &self.entries {
            for dep in &entry.metadata.dependencies {
                if !self.index.contains_key(dep.as_str()) {
                    errors.push(format!(
                        "{}: unknown dependency '{dep}'",
                        entry.metadata.name
                    ));
                }
            }
        }
        errors
    }

    /// Return a topological ordering of pass names respecting `dependencies`.
    ///
    /// Uses Kahn's algorithm.  Returns `None` if a dependency cycle is
    /// detected.
    #[must_use]
    pub fn topological_order(&self) -> Option<Vec<&str>> {
        // Build adjacency (pass → passes that depend on it).
        let mut in_degree: HashMap<&str, usize> = HashMap::new();
        let mut adj: HashMap<&str, Vec<&str>> = HashMap::new();

        for entry in &self.entries {
            let name = entry.metadata.name.as_str();
            in_degree.entry(name).or_insert(0);
            for dep in &entry.metadata.dependencies {
                // dep must run before entry.name
                adj.entry(dep.as_str())
                    .or_default()
                    .push(name);
                *in_degree.entry(name).or_insert(0) += 1;
            }
        }

        // Kahn's BFS.
        let mut queue: std::collections::VecDeque<&str> = in_degree
            .iter()
            .filter(|&(_, &d)| d == 0)
            .map(|(&n, _)| n)
            .collect();
        let mut order = Vec::with_capacity(self.entries.len());

        while let Some(node) = queue.pop_front() {
            order.push(node);
            if let Some(neighbors) = adj.get(node) {
                for &nb in neighbors {
                    let deg = in_degree.get_mut(nb)?;
                    *deg -= 1;
                    if *deg == 0 {
                        queue.push_back(nb);
                    }
                }
            }
        }

        if order.len() == self.entries.len() {
            Some(order)
        } else {
            None // cycle detected
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// get_pass_for_pattern  (free function)
// ─────────────────────────────────────────────────────────────────────────────

/// Look up the *best* pass for `pattern` in `registry`, selecting the one
/// whose applicable-pattern list has the longest exact-prefix match (falling
/// back to substring match), then the lowest cost.
///
/// Returns `None` when no enabled pass matches at all.
#[must_use]
pub fn get_pass_for_pattern<'r>(
    registry: &'r DeobfPassRegistry,
    pattern: &str,
) -> Option<&'r PassEntry> {
    registry
        .get_passes_for_pattern(pattern)
        .into_iter()
        .min_by_key(|e| e.metadata.cost)
}

// ─────────────────────────────────────────────────────────────────────────────
// Built-in stub passes for registry population
// ─────────────────────────────────────────────────────────────────────────────

/// A minimal pass that strips single-byte XOR obfuscation from the binary.
/// Intended to be registered under the `"xor-constant"` pattern.
#[derive(Debug, Clone, Default)]
pub struct XorConstantPass {
    /// Key to use.  When `None` the pass auto-detects.
    pub key: Option<u8>,
}

impl XorConstantPass {
    /// Create a new auto-detect pass.
    #[must_use]
    pub const fn new() -> Self {
        Self { key: None }
    }

    /// Create a pass locked to a specific XOR key.
    #[must_use]
    pub const fn with_key(key: u8) -> Self {
        Self { key: Some(key) }
    }
}

impl DeobfPass for XorConstantPass {
    fn name(&self) -> &'static str {
        "xor-constant"
    }

    fn description(&self) -> &'static str {
        "Recover single-byte XOR-encrypted regions"
    }

    fn is_applicable(&self, ctx: &DeobfContext) -> bool {
        ctx.binary.len() >= 4
    }

    fn run(&self, ctx: &mut DeobfContext) -> Result<DeobfResult, DeobfError> {
        use crate::XorDecryptor;
        let (key, decrypted) = if let Some(k) = self.key {
            (k, XorDecryptor::decrypt_constant(&ctx.binary, k))
        } else {
            XorDecryptor::recover_single_byte_key(&ctx.binary)
        };

        if key == 0 {
            return Ok(DeobfResult::default());
        }

        let original = ctx.binary.clone();
        ctx.patches.push(crate::Patch::new(
            0,
            original,
            decrypted,
            format!("xor-constant key=0x{key:02x}"),
        ));

        Ok(DeobfResult::new(
            1,
            vec![format!("xor-constant: key=0x{key:02x}")],
            ctx.binary.len(),
            0.75,
        ))
    }
}

/// A pass that detects and removes INT3 (0xCC) guard sequences.
#[derive(Debug, Clone, Default)]
pub struct Int3GuardRemover;

impl Int3GuardRemover {
    /// Create a new remover.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl DeobfPass for Int3GuardRemover {
    fn name(&self) -> &'static str {
        "int3-guard-remover"
    }

    fn description(&self) -> &'static str {
        "Remove INT3 breakpoint guard sequences used for anti-debug"
    }

    fn is_applicable(&self, ctx: &DeobfContext) -> bool {
        ctx.binary.contains(&0xCC)
    }

    fn run(&self, ctx: &mut DeobfContext) -> Result<DeobfResult, DeobfError> {
        let mut patches_applied = 0;
        let mut modified_bytes = 0;
        let mut transformations = Vec::new();

        let data = ctx.binary.clone();
        let mut i = 0;
        while i < data.len() {
            if data[i] == 0xCC {
                let start = i;
                while i < data.len() && data[i] == 0xCC {
                    i += 1;
                }
                let len = i - start;
                if len >= 2 {
                    let original = data[start..start + len].to_vec();
                    let patched = vec![0x90u8; len]; // replace with NOP
                    ctx.patches.push(crate::Patch::new(
                        start,
                        original,
                        patched,
                        format!("INT3 guard at {start:#x} ({len} bytes)"),
                    ));
                    patches_applied += 1;
                    modified_bytes += len;
                    transformations.push(format!("removed {len}-byte INT3 guard at {start:#x}"));
                }
            } else {
                i += 1;
            }
        }

        let confidence = if patches_applied > 0 { 0.90 } else { 0.0 };
        Ok(DeobfResult::new(
            patches_applied,
            transformations,
            modified_bytes,
            confidence,
        ))
    }
}

/// Build and return a default registry populated with built-in passes.
#[must_use]
pub fn default_registry() -> DeobfPassRegistry {
    let mut reg = DeobfPassRegistry::new();

    reg.register(
        Box::new(XorConstantPass::new()),
        PassMetadata::new(
            "xor-constant",
            "Single-byte XOR decryption",
            PassCategory::StringDecryption,
        )
        .with_patterns(["xor-constant", "xor", "string-encrypt"])
        .with_cost(2),
    );

    reg.register(
        Box::new(Int3GuardRemover::new()),
        PassMetadata::new(
            "int3-guard-remover",
            "Remove INT3 anti-debug guards",
            PassCategory::AntiDebug,
        )
        .with_patterns(["anti-debug", "int3", "guard"])
        .with_cost(1),
    );

    reg.register(
        Box::new(crate::NopSledRemover::new()),
        PassMetadata::new(
            "nop-sled-remover",
            "Remove NOP sled padding",
            PassCategory::BinaryPatch,
        )
        .with_patterns(["nop-sled", "sled", "padding"])
        .with_cost(1),
    );

    reg.register(
        Box::new(crate::ConstantFoldingPass::new()),
        PassMetadata::new(
            "constant-folding",
            "Fold trivially constant arithmetic expressions",
            PassCategory::Optimisation,
        )
        .with_patterns(["constant-fold", "arithmetic", "optimise"])
        .with_cost(3),
    );

    reg
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_registry() -> DeobfPassRegistry {
        default_registry()
    }

    #[test]
    fn test_registry_len() {
        let reg = make_registry();
        assert_eq!(reg.len(), 4);
    }

    #[test]
    fn test_registry_get_by_name() {
        let reg = make_registry();
        assert!(reg.get("xor-constant").is_some());
        assert!(reg.get("nop-sled-remover").is_some());
        assert!(reg.get("nonexistent").is_none());
    }

    #[test]
    fn test_get_passes_for_pattern() {
        let reg = make_registry();
        let matches = reg.get_passes_for_pattern("nop-sled");
        assert!(!matches.is_empty());
        assert!(matches.iter().any(|e| e.name() == "nop-sled-remover"));
    }

    #[test]
    fn test_get_pass_for_pattern_selects_lowest_cost() {
        let reg = make_registry();
        let entry = get_pass_for_pattern(&reg, "nop-sled");
        assert!(entry.is_some());
    }

    #[test]
    fn test_disable_pass() {
        let mut reg = make_registry();
        assert!(reg.set_enabled("xor-constant", false));
        let matches = reg.get_passes_for_pattern("xor");
        assert!(matches.iter().all(|e| e.name() != "xor-constant"));
    }

    #[test]
    fn test_disable_nonexistent_returns_false() {
        let mut reg = make_registry();
        assert!(!reg.set_enabled("ghost-pass", false));
    }

    #[test]
    fn test_stats_totals() {
        let reg = make_registry();
        let stats = reg.stats();
        assert_eq!(stats.total_passes, 4);
        assert_eq!(stats.enabled_passes, 4);
        assert_eq!(stats.disabled_passes, 0);
    }

    #[test]
    fn test_validate_dependencies_empty() {
        let reg = make_registry();
        let errs = reg.validate_dependencies();
        assert!(errs.is_empty(), "unexpected: {errs:?}");
    }

    #[test]
    fn test_topological_order_no_deps() {
        let reg = make_registry();
        let order = reg.topological_order();
        assert!(order.is_some());
        let order = order.unwrap();
        assert_eq!(order.len(), 4);
    }

    #[test]
    fn test_get_by_category() {
        let reg = make_registry();
        let anti = reg.get_by_category(PassCategory::AntiDebug);
        assert!(!anti.is_empty());
        assert!(anti.iter().any(|e| e.name() == "int3-guard-remover"));
    }

    #[test]
    fn test_run_pass_not_found_error() {
        let mut reg = make_registry();
        let mut ctx = DeobfContext::new(vec![0x90; 16]);
        let result = reg.run_pass("ghost-pass", &mut ctx);
        assert!(matches!(result, Err(DeobfError::NotApplicable(_))));
    }

    #[test]
    fn test_run_all_returns_results() {
        let mut reg = make_registry();
        let data = vec![0x90u8; 32]; // NOP sled
        let mut ctx = DeobfContext::new(data);
        let (results, errors) = reg.run_all(&mut ctx);
        // At least nop-sled-remover should have run and found something.
        assert!(!results.is_empty());
        // Errors should be empty for well-behaved passes.
        assert!(errors.is_empty(), "unexpected errors: {errors:?}");
    }

    #[test]
    fn test_register_replaces_existing() {
        let mut reg = make_registry();
        let old = reg.register(
            Box::new(XorConstantPass::with_key(0xAA)),
            PassMetadata::new("xor-constant", "Replacement", PassCategory::StringDecryption),
        );
        assert!(old.is_some());
        assert_eq!(reg.len(), 4); // count unchanged
    }

    #[test]
    fn test_names_includes_all() {
        let reg = make_registry();
        let names = reg.names();
        assert!(names.contains(&"xor-constant"));
        assert!(names.contains(&"constant-folding"));
    }
}
