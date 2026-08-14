//! Auto-apply FLIRT matches: bulk rename matched functions, propagate type
//! information from library prototypes, update call sites, generate application
//! report, handle partial matches.

use std::collections::HashMap;
use std::fmt::Write as _;

use crate::{FlirtMatch, FlirtMatcher, FlirtPattern, FlirtLibrary};
use rustre_core::address::Address;

// ── Types ──────────────────────────────────────────────────────────────────────

/// A rename action produced by auto-apply.
#[derive(Debug, Clone)]
pub struct RenameAction {
    /// The virtual address to rename.
    pub address: Address,
    /// Original name (empty if none).
    pub old_name: String,
    /// New name from the FLIRT match.
    pub new_name: String,
    /// Confidence of the underlying match.
    pub confidence: f32,
    /// Library that provided this name.
    pub library: String,
    /// Whether this rename was actually applied (may be false if skipped).
    pub applied: bool,
    /// Reason the rename was skipped (empty if applied).
    pub skip_reason: String,
}

impl RenameAction {
    /// Create a new rename action.
    #[must_use]
    pub const fn new(address: Address, old_name: String, new_name: String, confidence: f32, library: String) -> Self {
        Self { address, old_name, new_name, confidence, library, applied: false, skip_reason: String::new() }
    }

    /// Mark as applied.
    pub const fn mark_applied(&mut self) {
        self.applied = true;
    }

    /// Mark as skipped with a reason.
    pub fn mark_skipped(&mut self, reason: impl Into<String>) {
        self.skip_reason = reason.into();
    }
}

/// Type propagation info from a library prototype.
#[derive(Debug, Clone)]
pub struct TypePropagation {
    /// Target address that received the type.
    pub address: Address,
    /// Function or variable name.
    pub name: String,
    /// C-style prototype string (e.g. `"int __cdecl strcmp(const char *, const char *)"`)
    pub prototype: String,
    /// Whether this propagation was accepted.
    pub accepted: bool,
}

impl TypePropagation {
    /// Create a new type propagation record.
    #[must_use]
    pub fn new(address: Address, name: impl Into<String>, prototype: impl Into<String>) -> Self {
        Self { address, name: name.into(), prototype: prototype.into(), accepted: false }
    }
}

/// Result of applying FLIRT matches to a single function.
#[derive(Debug, Clone)]
pub struct ApplyResult {
    /// Address of the matched function.
    pub address: Address,
    /// Match used for this result.
    pub flirt_match: FlirtMatch,
    /// Rename that was (or would be) performed.
    pub rename: Option<RenameAction>,
    /// Type propagations for parameters.
    pub type_propagations: Vec<TypePropagation>,
    /// Whether any action was taken.
    pub any_action: bool,
}

impl ApplyResult {
    /// Create a result from a FLIRT match.
    #[must_use]
    pub const fn from_match(m: FlirtMatch) -> Self {
        let address = m.address;
        Self { address, flirt_match: m, rename: None, type_propagations: Vec::new(), any_action: false }
    }
}

/// A full application report summarizing the results of bulk auto-apply.
#[derive(Debug, Clone, Default)]
pub struct ApplicationReport {
    /// Total functions submitted.
    pub total_functions: usize,
    /// Functions that had at least one FLIRT match.
    pub matched_functions: usize,
    /// Successful renames.
    pub renames_applied: usize,
    /// Skipped renames (already named, low confidence, etc.).
    pub renames_skipped: usize,
    /// Type propagations accepted.
    pub types_propagated: usize,
    /// Per-function results.
    pub results: Vec<ApplyResult>,
    /// Errors encountered during application.
    pub errors: Vec<String>,
    /// Coverage percentage: `matched / total`.
    pub coverage_pct: f64,
}

impl ApplicationReport {
    /// Compute derived fields.
    pub fn finalize(&mut self) {
        if self.total_functions > 0 {
            self.coverage_pct = f64::from(u32::try_from(self.matched_functions).unwrap_or(u32::MAX))
                / f64::from(u32::try_from(self.total_functions).unwrap_or(u32::MAX)) * 100.0;
        }
    }

    /// Produce a human-readable summary string.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "FlirtAutoApply: {}/{} functions matched ({:.1}%), {} renames, {} types, {} skipped, {} errors",
            self.matched_functions, self.total_functions, self.coverage_pct,
            self.renames_applied, self.types_propagated, self.renames_skipped,
            self.errors.len()
        )
    }

    /// All successfully renamed addresses.
    #[must_use]
    pub fn renamed_addresses(&self) -> Vec<Address> {
        self.results.iter()
            .filter_map(|r| r.rename.as_ref().filter(|rn| rn.applied).map(|_| r.address))
            .collect()
    }

    /// All skipped rename actions.
    #[must_use]
    pub fn skipped_renames(&self) -> Vec<&RenameAction> {
        self.results.iter()
            .filter_map(|r| r.rename.as_ref().filter(|rn| !rn.applied))
            .collect()
    }
}

// ── ApplyConfig ───────────────────────────────────────────────────────────────

/// Configuration for the auto-apply process.
#[derive(Debug, Clone)]
pub struct ApplyConfig {
    /// Minimum confidence to apply a rename.
    pub min_confidence: f32,
    /// Skip renaming functions that already have a non-empty name.
    pub skip_already_named: bool,
    /// Apply type information when confidence is >= this threshold.
    pub type_apply_min_confidence: f32,
    /// Whether to handle partial matches (confidence below `min_confidence`).
    pub allow_partial_matches: bool,
    /// Name prefix to avoid renaming functions whose existing name starts with it
    /// (e.g. "sub_" = automatically generated names are OK to replace).
    pub auto_name_prefix: String,
    /// Whether to actually apply changes (false = dry-run mode).
    pub dry_run: bool,
}

impl Default for ApplyConfig {
    fn default() -> Self {
        Self {
            min_confidence: 0.8,
            skip_already_named: true,
            type_apply_min_confidence: 0.9,
            allow_partial_matches: false,
            auto_name_prefix: "sub_".to_string(),
            dry_run: false,
        }
    }
}

impl ApplyConfig {
    /// Create default configuration.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Enable dry-run mode.
    #[must_use]
    pub const fn dry_run(mut self) -> Self {
        self.dry_run = true;
        self
    }

    /// Set the minimum confidence.
    #[must_use]
    pub const fn min_confidence(mut self, c: f32) -> Self {
        self.min_confidence = c;
        self
    }

    /// Check whether an existing name should be replaced.
    ///
    /// An auto-generated name (`sub_XXXX`) is always replaceable.
    /// A real user-set name is only replaced if `skip_already_named` is false.
    #[must_use]
    pub fn should_rename(&self, existing_name: &str, new_name: &str) -> bool {
        if new_name.is_empty() {
            return false;
        }
        if existing_name.is_empty() {
            return true;
        }
        // Auto-generated names (e.g. "sub_1234") are always replaceable.
        if existing_name.starts_with(self.auto_name_prefix.as_str()) {
            return true;
        }
        // Already named: only replace if config says so.
        !self.skip_already_named
    }
}

// ── FlirtApplier ──────────────────────────────────────────────────────────────

/// Represents a function in the binary being analyzed.
#[derive(Debug, Clone)]
pub struct BinaryFunction {
    /// Start address.
    pub address: Address,
    /// Current name (empty if none).
    pub name: String,
    /// Raw bytes (enough for matching, typically 64+).
    pub bytes: Vec<u8>,
    /// Whether this function is already named by the user.
    pub user_named: bool,
}

impl BinaryFunction {
    /// Create a new function entry.
    #[must_use]
    pub const fn new(address: Address, bytes: Vec<u8>) -> Self {
        Self { address, name: String::new(), bytes, user_named: false }
    }

    /// Attach an existing name.
    #[must_use]
    pub fn with_name(mut self, name: impl Into<String>, user_named: bool) -> Self {
        self.name = name.into();
        self.user_named = user_named;
        self
    }
}

/// Prototype database: name -> prototype string.
pub type PrototypeDb = HashMap<String, String>;

/// Applies FLIRT matches in bulk to a set of binary functions.
pub struct FlirtApplier {
    /// Underlying matcher.
    pub matcher: FlirtMatcher,
    /// Prototype database for type propagation.
    pub prototypes: PrototypeDb,
    /// Configuration.
    pub config: ApplyConfig,
}

impl FlirtApplier {
    /// Create a new applier with an empty matcher.
    #[must_use]
    pub fn new(config: ApplyConfig) -> Self {
        Self { matcher: FlirtMatcher::new(), config, prototypes: HashMap::new() }
    }

    /// Create with an existing matcher.
    #[must_use]
    pub fn with_matcher(matcher: FlirtMatcher, config: ApplyConfig) -> Self {
        Self { matcher, config, prototypes: HashMap::new() }
    }

    /// Add a library to the matcher.
    pub fn add_library(&mut self, lib: FlirtLibrary) {
        self.matcher.add_library(lib);
    }

    /// Register a prototype for a function name.
    pub fn register_prototype(&mut self, name: impl Into<String>, proto: impl Into<String>) {
        self.prototypes.insert(name.into(), proto.into());
    }

    /// Apply FLIRT matches to a single function, producing an `ApplyResult`.
    #[must_use]
    pub fn apply_function(&self, func: &mut BinaryFunction) -> ApplyResult {
        let matches = self.matcher.match_function(func.address, &func.bytes);

        if matches.is_empty() {
            return ApplyResult::from_match(FlirtMatch {
                address: func.address,
                name: String::new(),
                offset: 0,
                library: String::new(),
                confidence: 0.0,
                is_public: false,
            });
        }

        // Pick best match. matches is non-empty (checked above), so max_by always returns Some.
        let best = match matches.iter().max_by(|a, b| {
            a.confidence.partial_cmp(&b.confidence).unwrap_or(std::cmp::Ordering::Equal)
        }) {
            Some(m) => m.clone(),
            None => return ApplyResult::from_match(FlirtMatch {
                address: func.address,
                name: String::new(),
                offset: 0,
                library: String::new(),
                confidence: 0.0,
                is_public: false,
            }),
        };

        let mut result = ApplyResult::from_match(best.clone());

        // Determine rename.
        if best.confidence >= self.config.min_confidence || self.config.allow_partial_matches {
            let mut action = RenameAction::new(
                func.address, func.name.clone(), best.name.clone(),
                best.confidence, best.library.clone(),
            );

            if self.config.should_rename(&func.name, &best.name) {
                if !self.config.dry_run {
                    func.name.clone_from(&best.name);
                }
                action.mark_applied();
                result.any_action = true;
            } else {
                action.mark_skipped(format!(
                    "existing name '{}' kept (skip_already_named={})",
                    func.name, self.config.skip_already_named
                ));
            }
            result.rename = Some(action);
        }

        // Type propagation.
        if best.confidence >= self.config.type_apply_min_confidence
            && let Some(proto) = self.prototypes.get(&best.name) {
                let mut tp = TypePropagation::new(func.address, &best.name, proto);
                tp.accepted = !self.config.dry_run;
                result.type_propagations.push(tp);
                result.any_action = true;
            }

        result
    }

    /// Apply FLIRT matches to all functions, returning a full `ApplicationReport`.
    #[must_use]
    pub fn apply_bulk(&self, functions: &mut [BinaryFunction]) -> ApplicationReport {
        let mut report = ApplicationReport { total_functions: functions.len(), ..ApplicationReport::default() };

        for func in functions.iter_mut() {
            let result = self.apply_function(func);
            if result.flirt_match.confidence > 0.0 {
                report.matched_functions += 1;
            }
            if let Some(ref rn) = result.rename {
                if rn.applied { report.renames_applied += 1; } else { report.renames_skipped += 1; }
            }
            report.types_propagated += result.type_propagations.iter().filter(|t| t.accepted).count();
            report.results.push(result);
        }

        report.finalize();
        report
    }

    /// Update call sites: find all CALL instructions in `code_bytes` that target
    /// addresses in `renamed_map`, and return a list of (`call_site_offset`, `new_name`) pairs.
    #[must_use]
    pub fn update_call_sites(
        &self,
        code_bytes: &[u8],
        base_address: Address,
        renamed_map: &HashMap<Address, String>,
    ) -> Vec<(usize, Address, String)> {
        // Simple heuristic: scan for E8 XX XX XX XX (near call) on x86/x86-64.
        let mut results = Vec::new();
        let len = code_bytes.len();
        for offset in 0..len.saturating_sub(4) {
            if code_bytes[offset] == 0xE8 {
                // Decode relative 32-bit offset.
                let rel = i64::from(i32::from_le_bytes([
                    code_bytes[offset+1], code_bytes[offset+2],
                    code_bytes[offset+3], code_bytes[offset+4],
                ]));
                let call_site_addr = base_address + offset as u64;
                let target = Address(call_site_addr.0.wrapping_add((rel + 5).cast_unsigned()));
                if let Some(name) = renamed_map.get(&target) {
                    results.push((offset, target, name.clone()));
                }
            }
        }
        results
    }

    /// Propagate names for non-public (local) functions referenced from a matched function.
    #[must_use]
    pub fn propagate_referenced_names(
        &self,
        patterns: &[FlirtPattern],
        function_bytes: &[u8],
        _base_addr: Address,
    ) -> Vec<(Address, String)> {
        let mut result = Vec::new();
        for pat in patterns {
            for rn in &pat.referenced_names {
                let off = rn.offset as usize;
                if off + 4 <= function_bytes.len() {
                    // Treat as an absolute 32-bit address embedded in the function.
                    let addr = u64::from(u32::from_le_bytes([
                        function_bytes[off], function_bytes[off+1],
                        function_bytes[off+2], function_bytes[off+3],
                    ]));
                    result.push((Address(addr), rn.name.clone()));
                }
            }
        }
        result
    }

    /// Handle partial matches: return functions where confidence is in
    /// `[min_partial, min_confidence)` with a "partial match" flag.
    #[must_use]
    pub fn collect_partial_matches(
        &self,
        functions: &[BinaryFunction],
        min_partial: f32,
    ) -> Vec<(Address, String, f32)> {
        let mut results = Vec::new();
        for func in functions {
            let matches = self.matcher.match_function(func.address, &func.bytes);
            for m in &matches {
                if m.confidence >= min_partial && m.confidence < self.config.min_confidence {
                    results.push((func.address, m.name.clone(), m.confidence));
                }
            }
        }
        results.sort_by(|a, b| b.2.partial_cmp(&a.2).unwrap_or(std::cmp::Ordering::Equal));
        results
    }
}

// ── Report formatting ──────────────────────────────────────────────────────────

/// Format an `ApplicationReport` as a plain-text table.
#[must_use]
pub fn format_report(report: &ApplicationReport) -> String {
    let mut out = String::new();
    out.push_str(&report.summary());
    out.push('\n');
    out.push_str(&"-".repeat(80));
    out.push('\n');
    let _ = writeln!(out, "{:<20} {:<30} {:<10} Library", "Address", "Name", "Confidence");
    out.push_str(&"-".repeat(80));
    out.push('\n');

    for r in &report.results {
        if r.flirt_match.confidence == 0.0 {
            continue;
        }
        let _ = writeln!(out,
            "0x{:<18x} {:<30} {:<10.2} {}",
            r.address, r.flirt_match.name, r.flirt_match.confidence, r.flirt_match.library
        );
        if let Some(rn) = &r.rename {
            let status = if rn.applied { "RENAMED".to_string() } else { format!("SKIPPED: {}", rn.skip_reason) };
            let _ = writeln!(out, "  {} {} -> {}", status, rn.old_name, rn.new_name);
        }
    }
    out
}

// ── Tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{FlirtLibrary, FlirtArch, FlirtOs, PatternByte};

    fn make_matcher_with_test_fn() -> FlirtMatcher {
        let mut lib = FlirtLibrary::new("libc", FlirtArch::X86, FlirtOs::Linux);
        let bytes = vec![
            PatternByte::Exact(0x55),
            PatternByte::Exact(0x8B),
            PatternByte::Exact(0xEC),
        ];
        let mut pat = crate::FlirtPattern::new(bytes);
        pat.names.push(crate::FlirtName {
            name: "my_func".into(), offset: 0, is_public: true, is_local: false,
        });
        lib.add_pattern(pat);
        let mut m = FlirtMatcher::new();
        m.add_library(lib);
        m
    }

    #[test]
    fn test_apply_single_function() {
        let matcher = make_matcher_with_test_fn();
        let config = ApplyConfig::new().min_confidence(0.5);
        let applier = FlirtApplier::with_matcher(matcher, config);

        let mut func = BinaryFunction::new(Address(0x1000), vec![0x55, 0x8B, 0xEC, 0x00, 0x00]);
        let result = applier.apply_function(&mut func);
        // Should have a match.
        assert!(!result.flirt_match.name.is_empty() || result.flirt_match.confidence > 0.0);
    }

    #[test]
    fn test_apply_config_should_rename_auto() {
        let cfg = ApplyConfig::new();
        assert!(cfg.should_rename("sub_1234", "my_func"));
        assert!(!cfg.should_rename("user_func", "my_func"));
        assert!(cfg.should_rename("", "my_func"));
    }

    #[test]
    fn test_apply_config_dry_run() {
        let cfg = ApplyConfig::new().dry_run();
        assert!(cfg.dry_run);
    }

    #[test]
    fn test_rename_action_apply_skip() {
        let mut action = RenameAction::new(Address(0x1000), "sub_1000".into(), "printf".into(), 0.95, "libc".into());
        assert!(!action.applied);
        action.mark_applied();
        assert!(action.applied);
        let mut action2 = RenameAction::new(Address(0x2000), "known_name".into(), "puts".into(), 0.9, "libc".into());
        action2.mark_skipped("skip_already_named=true");
        assert!(!action2.applied);
        assert!(!action2.skip_reason.is_empty());
    }

    #[test]
    fn test_update_call_sites() {
        let matcher = make_matcher_with_test_fn();
        let config = ApplyConfig::new();
        let applier = FlirtApplier::with_matcher(matcher, config);

        // E8 <rel32> near call: target = call_site + 5 + rel
        // At offset 0, base 0x1000. rel = 0x100 - 5 = 0xFB.
        // So bytes: E8 FB 00 00 00
        let code = vec![0xE8u8, 0xFB, 0x00, 0x00, 0x00, 0x00];
        let mut renamed = HashMap::new();
        renamed.insert(Address(0x1100), "target_fn".to_string());
        let sites = applier.update_call_sites(&code, Address(0x1000), &renamed);
        // target = 0x1000 + 0 + 5 + 0xFB = 0x1100
        assert_eq!(sites.len(), 1);
        assert_eq!(sites[0].2, "target_fn");
    }

    #[test]
    fn test_report_finalize() {
        let mut report = ApplicationReport::default();
        report.total_functions = 10;
        report.matched_functions = 8;
        report.finalize();
        assert!((report.coverage_pct - 80.0).abs() < 1e-9);
    }

    #[test]
    fn test_bulk_apply() {
        let matcher = make_matcher_with_test_fn();
        let config = ApplyConfig::new().min_confidence(0.5);
        let applier = FlirtApplier::with_matcher(matcher, config);

        let mut fns = vec![
            BinaryFunction::new(Address(0x1000), vec![0x55, 0x8B, 0xEC, 0x00]),
            BinaryFunction::new(Address(0x2000), vec![0x90, 0x90, 0x90, 0x90]),
        ];
        let report = applier.apply_bulk(&mut fns);
        assert_eq!(report.total_functions, 2);
    }
}
