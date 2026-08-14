//! `deobf_registry` — Metadata-only catalogue of available deobfuscation passes.
//!
//! Stores [`PassMetadata`] records (name, category, capability flags, cost tier,
//! dependencies) without holding live pass objects. Supports priority-ordered
//! queries by category or capability and automatic pass selection via
//! [`AutoSelector`] using binary-level trigger functions.
//!
//! # Relation to `deobf_pass_registry`
//! This module is a **metadata catalogue**: it never executes a pass and never
//! holds a `Box<dyn DeobfPass>`. It is suited for configuration UIs, preset
//! selection, and static analysis of the pass graph.
//!
//! [`deobf_pass_registry`](crate::deobf_pass_registry) is an **execution
//! registry**: it stores live pass objects and can run them via
//! [`DeobfPassRegistry::run_pass`] / [`DeobfPassRegistry::run_all`]. It also
//! provides dependency validation and topological ordering for pipeline
//! construction.

use std::collections::{HashMap, HashSet};
use std::fmt;

/// Boxed trigger function used by [`PassEntry`] to decide at runtime whether a
/// pass should run on a given binary.
pub type TriggerFn = Box<dyn Fn(&[u8]) -> bool + Send + Sync>;

// ─── PassCategory ─────────────────────────────────────────────────────────────

/// High-level category for grouping deobfuscation passes.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum PassCategory {
    /// String decryption / deobfuscation passes.
    StringDecryption,
    /// Control-flow obfuscation removal (opaque predicates, dispatcher removal).
    ControlFlow,
    /// Arithmetic expression simplification (MBA, constant folding).
    Arithmetic,
    /// Packing / compression removal.
    Packing,
    /// Anti-analysis / anti-debug removal.
    AntiAnalysis,
    /// Symbol recovery (import reconstruction, function naming).
    SymbolRecovery,
    /// Code virtualization / VM de-obfuscation.
    Virtualization,
    /// User-defined.
    Custom(String),
}

impl PassCategory {
    #[must_use]
    pub const fn label(&self) -> &str {
        match self {
            Self::StringDecryption => "string-decryption",
            Self::ControlFlow => "control-flow",
            Self::Arithmetic => "arithmetic",
            Self::Packing => "packing",
            Self::AntiAnalysis => "anti-analysis",
            Self::SymbolRecovery => "symbol-recovery",
            Self::Virtualization => "virtualization",
            Self::Custom(s) => s.as_str(),
        }
    }
}

impl fmt::Display for PassCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

// ─── PassCapability ───────────────────────────────────────────────────────────

/// Fine-grained capability flag for a deobfuscation pass.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum PassCapability {
    /// Recovers XOR-encrypted strings.
    XorStringDecryption,
    /// Recovers base64-encoded strings.
    Base64StringDecryption,
    /// Recovers RC4-encrypted strings.
    Rc4StringDecryption,
    /// Removes opaque predicates.
    OpaquePredicateRemoval,
    /// Removes junk code / dead code.
    JunkCodeRemoval,
    /// Simplifies constant arithmetic expressions.
    ConstantFolding,
    /// Simplifies mixed boolean-arithmetic.
    MbaSimplification,
    /// Removes NOP sleds.
    NopRemoval,
    /// Detects and removes anti-debugging tricks.
    AntiDebugRemoval,
    /// Reconstructs import tables.
    ImportReconstruction,
    /// Unpacks PE/ELF payloads.
    Unpacking,
    /// Reduces virtual machine bytecode to native code.
    VmLift,
    /// Custom capability string.
    Custom(String),
}

impl PassCapability {
    #[must_use]
    pub const fn label(&self) -> &str {
        match self {
            Self::XorStringDecryption => "xor-string-decryption",
            Self::Base64StringDecryption => "base64-string-decryption",
            Self::Rc4StringDecryption => "rc4-string-decryption",
            Self::OpaquePredicateRemoval => "opaque-predicate-removal",
            Self::JunkCodeRemoval => "junk-code-removal",
            Self::ConstantFolding => "constant-folding",
            Self::MbaSimplification => "mba-simplification",
            Self::NopRemoval => "nop-removal",
            Self::AntiDebugRemoval => "anti-debug-removal",
            Self::ImportReconstruction => "import-reconstruction",
            Self::Unpacking => "unpacking",
            Self::VmLift => "vm-lift",
            Self::Custom(s) => s.as_str(),
        }
    }
}

impl fmt::Display for PassCapability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

// ─── PassMetadata ─────────────────────────────────────────────────────────────

/// Metadata entry for a registered pass.
#[derive(Debug, Clone)]
pub struct PassMetadata {
    /// Unique pass name (key).
    pub name: String,
    /// Human-readable description.
    pub description: String,
    /// Execution priority (lower value = earlier execution).
    pub priority: u32,
    /// Category of the pass.
    pub category: PassCategory,
    /// Capabilities provided by this pass.
    pub capabilities: HashSet<PassCapability>,
    /// Pass names that must execute before this one.
    pub dependencies: Vec<String>,
    /// Whether the pass is enabled by default.
    pub enabled_by_default: bool,
    /// Estimated cost tier (Low/Medium/High) for resource planning.
    pub cost_tier: CostTier,
    /// Version string for the pass implementation.
    pub version: String,
    /// Author or origin of the pass.
    pub author: String,
}

impl PassMetadata {
    /// Construct a new `PassMetadata` with defaults.
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        description: impl Into<String>,
        priority: u32,
        category: PassCategory,
    ) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
            priority,
            category,
            capabilities: HashSet::new(),
            dependencies: Vec::new(),
            enabled_by_default: true,
            cost_tier: CostTier::Medium,
            version: "1.0".to_string(),
            author: String::new(),
        }
    }

    /// Add a capability to this pass.
    #[must_use]
    pub fn with_capability(mut self, cap: PassCapability) -> Self {
        self.capabilities.insert(cap);
        self
    }

    /// Add a dependency.
    #[must_use]
    pub fn with_dependency(mut self, dep: impl Into<String>) -> Self {
        self.dependencies.push(dep.into());
        self
    }

    /// Mark as disabled by default.
    #[must_use]
    pub const fn disabled_by_default(mut self) -> Self {
        self.enabled_by_default = false;
        self
    }

    /// Set cost tier.
    #[must_use]
    pub const fn with_cost(mut self, tier: CostTier) -> Self {
        self.cost_tier = tier;
        self
    }

    /// Returns `true` when this pass has the given capability.
    #[must_use]
    pub fn has_capability(&self, cap: &PassCapability) -> bool {
        self.capabilities.contains(cap)
    }
}

impl fmt::Display for PassMetadata {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PassMetadata({}, priority={}, category={}, capabilities={})",
            self.name,
            self.priority,
            self.category,
            self.capabilities.len(),
        )
    }
}

// ─── CostTier ─────────────────────────────────────────────────────────────────

/// Resource cost estimate for a pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CostTier {
    /// Fast, O(n) in binary size.
    Low,
    /// Moderate; suitable for interactive analysis.
    Medium,
    /// Expensive; may involve SAT solving, emulation, etc.
    High,
}

impl fmt::Display for CostTier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Low => f.write_str("Low"),
            Self::Medium => f.write_str("Medium"),
            Self::High => f.write_str("High"),
        }
    }
}

// ─── PassEntry ────────────────────────────────────────────────────────────────

/// An entry in the registry combining metadata with an optional binary trigger
/// function (used by `AutoSelector`).
pub struct PassEntry {
    /// Metadata about the pass.
    pub metadata: PassMetadata,
    /// An optional function that, given a binary, returns `true` when the pass
    /// is likely to be productive.
    pub should_run: Option<TriggerFn>,
}

impl PassEntry {
    /// Create a new entry from metadata with no auto-selector trigger.
    #[must_use]
    pub fn new(metadata: PassMetadata) -> Self {
        Self {
            metadata,
            should_run: None,
        }
    }

    /// Create an entry with an auto-selector trigger function.
    #[must_use]
    pub fn with_trigger<F>(metadata: PassMetadata, f: F) -> Self
    where
        F: Fn(&[u8]) -> bool + Send + Sync + 'static,
    {
        Self {
            metadata,
            should_run: Some(Box::new(f)),
        }
    }

    /// Returns `true` when the pass has a trigger and the trigger fires.
    #[must_use]
    pub fn triggers_on(&self, binary: &[u8]) -> bool {
        self.should_run.as_ref().is_none_or(|f| f(binary))
    }
}

impl fmt::Debug for PassEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PassEntry")
            .field("metadata", &self.metadata)
            .field("has_trigger", &self.should_run.is_some())
            .finish()
    }
}

// ─── DeobfRegistry ────────────────────────────────────────────────────────────

/// Registry of available deobfuscation passes.
///
/// Passes are registered with metadata and an optional binary trigger.
/// The registry supports:
/// - Query by name, category, capability.
/// - Priority-ordered selection.
/// - Automatic pass selection based on binary analysis.
pub struct DeobfRegistry {
    entries: HashMap<String, PassEntry>,
}

impl DeobfRegistry {
    /// Create an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    /// Create a registry pre-loaded with built-in pass metadata.
    #[must_use]
    pub fn with_builtins() -> Self {
        let mut reg = Self::new();
        reg.populate_builtins();
        reg
    }

    /// Register a `PassEntry`. Replaces any existing entry with the same name.
    pub fn register(&mut self, entry: PassEntry) -> Option<PassEntry> {
        self.entries.insert(entry.metadata.name.clone(), entry)
    }

    /// Register a `PassMetadata` without a trigger.
    pub fn register_metadata(&mut self, meta: PassMetadata) {
        self.entries.insert(meta.name.clone(), PassEntry::new(meta));
    }

    /// Deregister a pass by name. Returns the removed entry if it existed.
    pub fn deregister(&mut self, name: &str) -> Option<PassEntry> {
        self.entries.remove(name)
    }

    /// Look up a pass by name.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&PassEntry> {
        self.entries.get(name)
    }

    /// Number of registered passes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` when the registry is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Return all pass names, sorted alphabetically.
    #[must_use]
    pub fn names(&self) -> Vec<&str> {
        let mut names: Vec<&str> = self.entries.keys().map(String::as_str).collect();
        names.sort_unstable();
        names
    }

    /// Return all passes in a given category, sorted by priority (ascending).
    #[must_use]
    pub fn by_category(&self, category: &PassCategory) -> Vec<&PassEntry> {
        let mut entries: Vec<&PassEntry> = self
            .entries
            .values()
            .filter(|e| &e.metadata.category == category)
            .collect();
        entries.sort_by_key(|e| e.metadata.priority);
        entries
    }

    /// Return all passes that provide a given capability, sorted by priority.
    #[must_use]
    pub fn by_capability(&self, cap: &PassCapability) -> Vec<&PassEntry> {
        let mut entries: Vec<&PassEntry> = self
            .entries
            .values()
            .filter(|e| e.metadata.has_capability(cap))
            .collect();
        entries.sort_by_key(|e| e.metadata.priority);
        entries
    }

    /// Return all passes, sorted by priority ascending then by name.
    #[must_use]
    pub fn all_by_priority(&self) -> Vec<&PassEntry> {
        let mut entries: Vec<&PassEntry> = self.entries.values().collect();
        entries.sort_by(|a, b| {
            a.metadata
                .priority
                .cmp(&b.metadata.priority)
                .then(a.metadata.name.cmp(&b.metadata.name))
        });
        entries
    }

    /// Return the names of all enabled-by-default passes, sorted by priority.
    #[must_use]
    pub fn default_enabled(&self) -> Vec<&str> {
        let mut entries: Vec<&PassEntry> = self
            .entries
            .values()
            .filter(|e| e.metadata.enabled_by_default)
            .collect();
        entries.sort_by_key(|e| e.metadata.priority);
        entries.into_iter().map(|e| e.metadata.name.as_str()).collect()
    }

    /// Enable a pass by name (sets `enabled_by_default = true`).
    pub fn enable(&mut self, name: &str) -> bool {
        if let Some(entry) = self.entries.get_mut(name) {
            entry.metadata.enabled_by_default = true;
            true
        } else {
            false
        }
    }

    /// Disable a pass by name (sets `enabled_by_default = false`).
    pub fn disable(&mut self, name: &str) -> bool {
        if let Some(entry) = self.entries.get_mut(name) {
            entry.metadata.enabled_by_default = false;
            true
        } else {
            false
        }
    }

    /// Populate the registry with built-in pass metadata.
    fn populate_builtins(&mut self) {
        let builtins: Vec<PassMetadata> = vec![
            // xor-string-decrypt
            PassMetadata::new(
                "xor-string-decrypt",
                "Decrypt XOR-obfuscated strings using single-byte and multi-byte key recovery.",
                100,
                PassCategory::StringDecryption,
            )
            .with_capability(PassCapability::XorStringDecryption)
            .with_cost(CostTier::Low),
            // base64-decode
            PassMetadata::new(
                "base64-decode",
                "Find and decode base64-encoded blobs embedded in the binary.",
                110,
                PassCategory::StringDecryption,
            )
            .with_capability(PassCapability::Base64StringDecryption)
            .with_cost(CostTier::Low),
            // rc4-decrypt
            PassMetadata::new(
                "rc4-decrypt",
                "Attempt RC4 string decryption by brute-forcing short keys.",
                150,
                PassCategory::StringDecryption,
            )
            .with_capability(PassCapability::Rc4StringDecryption)
            .with_cost(CostTier::Medium),
            // nop-sled-remover
            PassMetadata::new(
                "nop-sled-remover",
                "Remove NOP sled regions from the binary.",
                50,
                PassCategory::ControlFlow,
            )
            .with_capability(PassCapability::NopRemoval)
            .with_cost(CostTier::Low),
            // constant-folding
            PassMetadata::new(
                "constant-folding",
                "Replace trivially constant arithmetic expressions with computed values.",
                200,
                PassCategory::Arithmetic,
            )
            .with_capability(PassCapability::ConstantFolding)
            .with_cost(CostTier::Low),
            // mba-simplification
            PassMetadata::new(
                "mba-simplification",
                "Simplify mixed boolean-arithmetic (MBA) expressions.",
                250,
                PassCategory::Arithmetic,
            )
            .with_capability(PassCapability::MbaSimplification)
            .with_cost(CostTier::High)
            .disabled_by_default(),
            // junk-code-removal
            PassMetadata::new(
                "junk-code-removal",
                "Remove dead / junk code inserted by obfuscators.",
                300,
                PassCategory::ControlFlow,
            )
            .with_capability(PassCapability::JunkCodeRemoval)
            .with_cost(CostTier::Medium),
            // anti-debug-removal
            PassMetadata::new(
                "anti-debug-removal",
                "Patch common anti-debugging constructs (IsDebuggerPresent, timing checks).",
                350,
                PassCategory::AntiAnalysis,
            )
            .with_capability(PassCapability::AntiDebugRemoval)
            .with_cost(CostTier::Low),
            // import-reconstruction
            PassMetadata::new(
                "import-reconstruction",
                "Reconstruct import address table from resolved API hashes.",
                400,
                PassCategory::SymbolRecovery,
            )
            .with_capability(PassCapability::ImportReconstruction)
            .with_cost(CostTier::Medium),
        ];

        for meta in builtins {
            self.register_metadata(meta);
        }

        // Register a pass with a trigger.
        let entry = PassEntry::with_trigger(
            PassMetadata::new(
                "upx-unpack",
                "Detect and unpack UPX-compressed PE binaries.",
                10,
                PassCategory::Packing,
            )
            .with_capability(PassCapability::Unpacking)
            .with_cost(CostTier::Medium),
            |binary| {
                binary.windows(4).any(|w| w == b"UPX!")
                    || binary
                        .windows(4)
                        .any(|w| w == b"UPX0" || w == b"UPX1")
            },
        );
        self.register(entry);
    }
}

impl Default for DeobfRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for DeobfRegistry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeobfRegistry")
            .field("pass_count", &self.entries.len())
            .finish_non_exhaustive()
    }
}

// ─── AutoSelector ─────────────────────────────────────────────────────────────

/// Analyzes a binary and selects the most appropriate passes from a registry.
pub struct AutoSelector<'a> {
    registry: &'a DeobfRegistry,
    /// Maximum number of passes to select.
    pub max_passes: usize,
    /// Maximum cost tier to include (exclusive of tiers above).
    pub max_cost: CostTier,
    /// Whether to include disabled-by-default passes when triggered.
    pub include_disabled_if_triggered: bool,
}

/// Result of automatic pass selection.
#[derive(Debug, Clone)]
pub struct SelectionResult {
    /// Names of selected passes in priority order.
    pub selected: Vec<String>,
    /// Rationale for each selected pass.
    pub rationale: HashMap<String, String>,
    /// Number of passes considered but excluded.
    pub excluded_count: usize,
}

impl SelectionResult {
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "AutoSelector: selected {}/{} passes",
            self.selected.len(),
            self.selected.len() + self.excluded_count,
        )
    }
}

impl<'a> AutoSelector<'a> {
    /// Create a new `AutoSelector` for the given registry.
    #[must_use]
    pub const fn new(registry: &'a DeobfRegistry) -> Self {
        Self {
            registry,
            max_passes: 20,
            max_cost: CostTier::High,
            include_disabled_if_triggered: true,
        }
    }

    /// Select passes appropriate for `binary`, sorted by priority.
    #[must_use]
    pub fn select(&self, binary: &[u8]) -> SelectionResult {
        let mut selected: Vec<String> = Vec::new();
        let mut rationale: HashMap<String, String> = HashMap::new();
        let mut excluded = 0usize;

        // All passes sorted by priority.
        let ordered = self.registry.all_by_priority();

        for entry in ordered {
            if selected.len() >= self.max_passes {
                excluded += 1;
                continue;
            }

            // Cost filter.
            if self.is_too_costly(&entry.metadata.cost_tier) {
                excluded += 1;
                continue;
            }

            let triggered = entry.triggers_on(binary);
            let enabled = entry.metadata.enabled_by_default;

            if enabled || (self.include_disabled_if_triggered && triggered) {
                let reason = if triggered && !enabled {
                    format!(
                        "disabled by default but triggered by binary analysis ({})",
                        entry.metadata.capabilities.iter().map(PassCapability::label).collect::<Vec<_>>().join(", ")
                    )
                } else if triggered {
                    "enabled and triggered by binary analysis".to_string()
                } else {
                    "enabled by default".to_string()
                };
                selected.push(entry.metadata.name.clone());
                rationale.insert(entry.metadata.name.clone(), reason);
            } else {
                excluded += 1;
            }
        }

        SelectionResult {
            selected,
            rationale,
            excluded_count: excluded,
        }
    }

    const fn is_too_costly(&self, tier: &CostTier) -> bool {
        matches!(
            (&self.max_cost, tier),
            (CostTier::Low, CostTier::Medium | CostTier::High) | (CostTier::Medium, CostTier::High)
        )
    }

    /// Query a specific category from the registry for passes relevant to `binary`.
    #[must_use]
    pub fn select_by_category(
        &self,
        category: &PassCategory,
        binary: &[u8],
    ) -> Vec<&PassEntry> {
        self.registry
            .by_category(category)
            .into_iter()
            .filter(|e| {
                (e.metadata.enabled_by_default || (self.include_disabled_if_triggered && e.triggers_on(binary)))
                    && !self.is_too_costly(&e.metadata.cost_tier)
            })
            .collect()
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pass_category_label() {
        assert_eq!(PassCategory::StringDecryption.label(), "string-decryption");
        assert_eq!(
            PassCategory::Custom("x".to_string()).label(),
            "x"
        );
    }

    #[test]
    fn pass_capability_label() {
        assert_eq!(PassCapability::XorStringDecryption.label(), "xor-string-decryption");
        assert_eq!(PassCapability::Custom("foo".to_string()).label(), "foo");
    }

    #[test]
    fn pass_metadata_new() {
        let m = PassMetadata::new("test", "desc", 100, PassCategory::Arithmetic)
            .with_capability(PassCapability::ConstantFolding);
        assert_eq!(m.name, "test");
        assert!(m.has_capability(&PassCapability::ConstantFolding));
        assert!(!m.has_capability(&PassCapability::NopRemoval));
    }

    #[test]
    fn pass_metadata_disabled_by_default() {
        let m = PassMetadata::new("x", "y", 1, PassCategory::Arithmetic).disabled_by_default();
        assert!(!m.enabled_by_default);
    }

    #[test]
    fn pass_entry_triggers_on_no_trigger() {
        let entry = PassEntry::new(PassMetadata::new("e", "d", 1, PassCategory::Packing));
        // No trigger → always triggers.
        assert!(entry.triggers_on(&[0u8; 32]));
    }

    #[test]
    fn pass_entry_triggers_on_with_trigger() {
        let entry = PassEntry::with_trigger(
            PassMetadata::new("e", "d", 1, PassCategory::Packing),
            |data| data.contains(&0xAA),
        );
        assert!(!entry.triggers_on(&[0x00u8; 8]));
        assert!(entry.triggers_on(&[0xAAu8, 0x00]));
    }

    #[test]
    fn registry_empty() {
        let reg = DeobfRegistry::new();
        assert!(reg.is_empty());
        assert_eq!(reg.len(), 0);
    }

    #[test]
    fn registry_register_and_get() {
        let mut reg = DeobfRegistry::new();
        let meta = PassMetadata::new("p1", "desc", 10, PassCategory::ControlFlow);
        reg.register_metadata(meta);
        assert_eq!(reg.len(), 1);
        let entry = reg.get("p1").unwrap();
        assert_eq!(entry.metadata.name, "p1");
    }

    #[test]
    fn registry_deregister() {
        let mut reg = DeobfRegistry::new();
        reg.register_metadata(PassMetadata::new("p1", "d", 1, PassCategory::ControlFlow));
        let removed = reg.deregister("p1");
        assert!(removed.is_some());
        assert!(reg.is_empty());
    }

    #[test]
    fn registry_names_sorted() {
        let mut reg = DeobfRegistry::new();
        reg.register_metadata(PassMetadata::new("z", "d", 3, PassCategory::ControlFlow));
        reg.register_metadata(PassMetadata::new("a", "d", 1, PassCategory::ControlFlow));
        reg.register_metadata(PassMetadata::new("m", "d", 2, PassCategory::ControlFlow));
        let names = reg.names();
        assert_eq!(names, vec!["a", "m", "z"]);
    }

    #[test]
    fn registry_by_category() {
        let mut reg = DeobfRegistry::new();
        reg.register_metadata(PassMetadata::new("s1", "d", 5, PassCategory::StringDecryption));
        reg.register_metadata(PassMetadata::new("s2", "d", 3, PassCategory::StringDecryption));
        reg.register_metadata(PassMetadata::new("c1", "d", 1, PassCategory::ControlFlow));
        let string_passes = reg.by_category(&PassCategory::StringDecryption);
        assert_eq!(string_passes.len(), 2);
        // Sorted by priority.
        assert!(string_passes[0].metadata.priority <= string_passes[1].metadata.priority);
    }

    #[test]
    fn registry_by_capability() {
        let mut reg = DeobfRegistry::new();
        let m1 = PassMetadata::new("p1", "d", 5, PassCategory::StringDecryption)
            .with_capability(PassCapability::XorStringDecryption);
        let m2 = PassMetadata::new("p2", "d", 3, PassCategory::StringDecryption);
        reg.register_metadata(m1);
        reg.register_metadata(m2);
        let xor_passes = reg.by_capability(&PassCapability::XorStringDecryption);
        assert_eq!(xor_passes.len(), 1);
        assert_eq!(xor_passes[0].metadata.name, "p1");
    }

    #[test]
    fn registry_all_by_priority() {
        let mut reg = DeobfRegistry::new();
        reg.register_metadata(PassMetadata::new("b", "d", 2, PassCategory::ControlFlow));
        reg.register_metadata(PassMetadata::new("a", "d", 1, PassCategory::ControlFlow));
        let all = reg.all_by_priority();
        assert_eq!(all[0].metadata.priority, 1);
        assert_eq!(all[1].metadata.priority, 2);
    }

    #[test]
    fn registry_default_enabled() {
        let mut reg = DeobfRegistry::new();
        reg.register_metadata(PassMetadata::new("e", "d", 1, PassCategory::ControlFlow));
        reg.register_metadata(
            PassMetadata::new("d", "d", 2, PassCategory::ControlFlow).disabled_by_default(),
        );
        let enabled = reg.default_enabled();
        assert_eq!(enabled, vec!["e"]);
    }

    #[test]
    fn registry_enable_disable() {
        let mut reg = DeobfRegistry::new();
        reg.register_metadata(PassMetadata::new("p", "d", 1, PassCategory::ControlFlow));
        reg.disable("p");
        assert!(!reg.get("p").unwrap().metadata.enabled_by_default);
        reg.enable("p");
        assert!(reg.get("p").unwrap().metadata.enabled_by_default);
    }

    #[test]
    fn registry_with_builtins() {
        let reg = DeobfRegistry::with_builtins();
        assert!(reg.len() >= 9);
        assert!(reg.get("xor-string-decrypt").is_some());
        assert!(reg.get("upx-unpack").is_some());
    }

    #[test]
    fn auto_selector_selects_enabled() {
        let reg = DeobfRegistry::with_builtins();
        let selector = AutoSelector::new(&reg);
        let result = selector.select(&[0u8; 64]);
        assert!(!result.selected.is_empty());
        assert!(result.selected.contains(&"xor-string-decrypt".to_string()));
    }

    #[test]
    fn auto_selector_upx_trigger() {
        let reg = DeobfRegistry::with_builtins();
        let selector = AutoSelector::new(&reg);
        let mut binary = vec![0u8; 256];
        binary[100..104].copy_from_slice(b"UPX!");
        let result = selector.select(&binary);
        assert!(result.selected.contains(&"upx-unpack".to_string()));
    }

    #[test]
    fn auto_selector_cost_filter() {
        let mut reg = DeobfRegistry::new();
        reg.register_metadata(
            PassMetadata::new("low", "d", 1, PassCategory::ControlFlow)
                .with_cost(CostTier::Low),
        );
        reg.register_metadata(
            PassMetadata::new("high", "d", 2, PassCategory::ControlFlow)
                .with_cost(CostTier::High),
        );
        let mut selector = AutoSelector::new(&reg);
        selector.max_cost = CostTier::Low;
        let result = selector.select(&[0u8; 64]);
        assert!(result.selected.contains(&"low".to_string()));
        assert!(!result.selected.contains(&"high".to_string()));
    }

    #[test]
    fn auto_selector_select_by_category() {
        let reg = DeobfRegistry::with_builtins();
        let selector = AutoSelector::new(&reg);
        let passes = selector.select_by_category(&PassCategory::StringDecryption, &[0u8; 64]);
        assert!(!passes.is_empty());
    }

    #[test]
    fn selection_result_summary() {
        let result = SelectionResult {
            selected: vec!["a".to_string(), "b".to_string()],
            rationale: HashMap::new(),
            excluded_count: 3,
        };
        let s = result.summary();
        assert!(s.contains("2/5"));
    }

    #[test]
    fn registry_debug_format() {
        let reg = DeobfRegistry::new();
        let _ = format!("{reg:?}");
    }

    #[test]
    fn cost_tier_display() {
        assert_eq!(CostTier::Low.to_string(), "Low");
        assert_eq!(CostTier::High.to_string(), "High");
    }
}
