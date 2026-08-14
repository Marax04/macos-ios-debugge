//! Loader plugin registry.
//!
//! Register loaders by file format, priority-based selection, loader capability
//! queries, lazy-initialization support, and loader statistics.

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, RwLock};

// ─────────────────────────────────────────────────────────────────────────────
// LoaderCapability
// ─────────────────────────────────────────────────────────────────────────────

/// A capability that a loader may or may not support.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LoaderCapability {
    /// Can read sections from the binary.
    ReadSections,
    /// Can read the symbol table.
    ReadSymbols,
    /// Can read the import table.
    ReadImports,
    /// Can read the export table.
    ReadExports,
    /// Can read DWARF / debug information.
    ReadDebugInfo,
    /// Can identify relocations.
    ReadRelocations,
    /// Can extract embedded / nested binaries.
    ReadNested,
    /// Can decode / decompress packed data.
    Unpack,
    /// Can detect anti-analysis tricks.
    DetectAntiAnalysis,
    /// Can produce a linear disassembly stream.
    Disassemble,
    /// Supports streaming / partial loading.
    Streaming,
    /// Can apply patches and write back.
    PatchWrite,
}

impl fmt::Display for LoaderCapability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::ReadSections => "read_sections",
            Self::ReadSymbols => "read_symbols",
            Self::ReadImports => "read_imports",
            Self::ReadExports => "read_exports",
            Self::ReadDebugInfo => "read_debug_info",
            Self::ReadRelocations => "read_relocations",
            Self::ReadNested => "read_nested",
            Self::Unpack => "unpack",
            Self::DetectAntiAnalysis => "detect_anti_analysis",
            Self::Disassemble => "disassemble",
            Self::Streaming => "streaming",
            Self::PatchWrite => "patch_write",
        };
        write!(f, "{s}")
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// LoaderPriority
// ─────────────────────────────────────────────────────────────────────────────

/// Priority class for loader selection.
///
/// When multiple loaders can handle the same input, the one with the highest
/// priority (lowest numeric value) is selected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LoaderPriority {
    /// Definitively handles this format (magic + structural validation).
    Definitive = 0,
    /// High confidence (magic match only).
    High = 10,
    /// Medium confidence (extension heuristic).
    Medium = 50,
    /// Low confidence (fallback / catch-all).
    Low = 100,
    /// Last resort.
    Fallback = 255,
}

impl fmt::Display for LoaderPriority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Definitive => write!(f, "definitive"),
            Self::High => write!(f, "high"),
            Self::Medium => write!(f, "medium"),
            Self::Low => write!(f, "low"),
            Self::Fallback => write!(f, "fallback"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// FormatTag
// ─────────────────────────────────────────────────────────────────────────────

/// Identifies a binary format for registry lookup.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum FormatTag {
    Elf,
    Pe,
    MachO,
    Wasm,
    LuaBytecode,
    JavaClass,
    Dex,
    Pdf,
    Zip,
    OleDoc,
    Llvm,
    DotNet,
    Pyc,
    Dex35,
    Coff,
    Unknown,
    Custom(String),
}

impl fmt::Display for FormatTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Elf => write!(f, "elf"),
            Self::Pe => write!(f, "pe"),
            Self::MachO => write!(f, "macho"),
            Self::Wasm => write!(f, "wasm"),
            Self::LuaBytecode => write!(f, "lua"),
            Self::JavaClass => write!(f, "java-class"),
            Self::Dex => write!(f, "dex"),
            Self::Pdf => write!(f, "pdf"),
            Self::Zip => write!(f, "zip"),
            Self::OleDoc => write!(f, "ole"),
            Self::Llvm => write!(f, "llvm-bc"),
            Self::DotNet => write!(f, "dotnet"),
            Self::Pyc => write!(f, "pyc"),
            Self::Dex35 => write!(f, "dex35"),
            Self::Coff => write!(f, "coff"),
            Self::Unknown => write!(f, "unknown"),
            Self::Custom(s) => write!(f, "{s}"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// LoaderPlugin trait
// ─────────────────────────────────────────────────────────────────────────────

/// Trait implemented by every loader plugin.
pub trait LoaderPlugin: Send + Sync + fmt::Debug {
    /// Unique name (e.g. `"elf"`, `"pe-rich"`, `"packed-upx"`).
    fn name(&self) -> &str;

    /// Human-readable description.
    fn description(&self) -> &str;

    /// File format(s) this loader handles.
    fn formats(&self) -> &[FormatTag];

    /// File extensions this loader typically handles (without `.`).
    fn extensions(&self) -> &[&str];

    /// Probe `data` and return a confidence score 0–255.
    ///
    /// 0 = cannot handle, 255 = perfect match.
    fn probe(&self, data: &[u8]) -> u8;

    /// Capabilities advertised by this loader.
    fn capabilities(&self) -> &[LoaderCapability];

    /// Whether this loader supports streaming (partial data loading).
    fn supports_streaming(&self) -> bool {
        self.capabilities().contains(&LoaderCapability::Streaming)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// LoaderEntry
// ─────────────────────────────────────────────────────────────────────────────

/// An entry in the registry combining a plugin with its metadata.
#[derive(Debug, Clone)]
pub struct LoaderEntry {
    /// The plugin itself.
    pub plugin: Arc<dyn LoaderPlugin>,
    /// Registration priority.
    pub priority: LoaderPriority,
    /// Whether the loader is enabled.
    pub enabled: bool,
    /// Number of times this loader was selected by `auto_select`.
    pub select_count: u64,
    /// Number of successful loads via this loader.
    pub success_count: u64,
    /// Number of failed loads via this loader.
    pub failure_count: u64,
}

impl LoaderEntry {
    /// Create a new entry with the given priority.
    pub fn new(plugin: Arc<dyn LoaderPlugin>, priority: LoaderPriority) -> Self {
        Self {
            plugin,
            priority,
            enabled: true,
            select_count: 0,
            success_count: 0,
            failure_count: 0,
        }
    }

    /// Total load attempts for this loader.
    #[must_use] 
    pub const fn total_attempts(&self) -> u64 {
        self.success_count + self.failure_count
    }

    /// Success rate as a fraction 0.0–1.0.
    #[must_use] 
    pub fn success_rate(&self) -> f64 {
        let total = self.total_attempts();
        if total == 0 {
            0.0
        } else {
            f64::from(u32::try_from(self.success_count).unwrap_or(u32::MAX))
                / f64::from(u32::try_from(total).unwrap_or(u32::MAX))
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// RegistryStats
// ─────────────────────────────────────────────────────────────────────────────

/// Aggregate statistics across all registered loaders.
#[derive(Debug, Default, Clone)]
pub struct RegistryStats {
    /// Total number of registered loaders.
    pub total_loaders: usize,
    /// Number of enabled loaders.
    pub enabled_loaders: usize,
    /// Total select events across all loaders.
    pub total_selects: u64,
    /// Total successful loads.
    pub total_successes: u64,
    /// Total failed loads.
    pub total_failures: u64,
    /// Per-format loader counts.
    pub format_counts: HashMap<String, usize>,
}

impl RegistryStats {
    /// Overall success rate.
    #[must_use] 
    pub fn success_rate(&self) -> f64 {
        let attempts = self.total_successes + self.total_failures;
        if attempts == 0 {
            0.0
        } else {
            f64::from(u32::try_from(self.total_successes).unwrap_or(u32::MAX))
                / f64::from(u32::try_from(attempts).unwrap_or(u32::MAX))
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ProbeResult
// ─────────────────────────────────────────────────────────────────────────────

/// Result of probing a single loader against input data.
#[derive(Debug, Clone)]
pub struct ProbeResult {
    /// Name of the loader.
    pub loader_name: String,
    /// Confidence score 0–255.
    pub confidence: u8,
    /// Priority of the loader entry.
    pub priority: LoaderPriority,
}

impl ProbeResult {
    /// Effective ranking key: lower priority value wins; higher confidence wins
    /// within the same priority class.
    #[must_use] 
    pub const fn rank_key(&self) -> (u8, std::cmp::Reverse<u8>) {
        (self.priority as u8, std::cmp::Reverse(self.confidence))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// LoaderRegistry
// ─────────────────────────────────────────────────────────────────────────────

/// Central registry for loader plugins.
///
/// Thread-safe via interior `RwLock`.
pub struct PluginRegistry {
    entries: RwLock<Vec<LoaderEntry>>,
}

impl Default for PluginRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl PluginRegistry {
    /// Create a new empty registry.
    #[must_use] 
    pub const fn new() -> Self {
        Self {
            entries: RwLock::new(Vec::new()),
        }
    }

    /// Register a loader plugin with the given priority.
    ///
    /// # Panics
    /// Panics if the internal lock is poisoned.
    pub fn register(&self, plugin: Arc<dyn LoaderPlugin>, priority: LoaderPriority) {
        let mut entries = self.entries.write().unwrap();
        // Avoid duplicate registrations by name.
        if entries.iter().any(|e| e.plugin.name() == plugin.name()) {
            return;
        }
        entries.push(LoaderEntry::new(plugin, priority));
    }

    /// Register with default `LoaderPriority::High` priority.
    ///
    /// # Panics
    /// Panics if the internal lock is poisoned.
    pub fn register_default(&self, plugin: Arc<dyn LoaderPlugin>) {
        self.register(plugin, LoaderPriority::High);
    }

    /// Unregister a loader by name. Returns `true` if it was found.
    ///
    /// # Panics
    /// Panics if the internal lock is poisoned.
    pub fn unregister(&self, name: &str) -> bool {
        let mut entries = self.entries.write().unwrap();
        let before = entries.len();
        entries.retain(|e| e.plugin.name() != name);
        entries.len() < before
    }

    /// Enable or disable a loader by name.
    ///
    /// # Panics
    /// Panics if the internal lock is poisoned.
    pub fn set_enabled(&self, name: &str, enabled: bool) -> bool {
        let mut entries = self.entries.write().unwrap();
        if let Some(e) = entries.iter_mut().find(|e| e.plugin.name() == name) {
            e.enabled = enabled;
            true
        } else {
            false
        }
    }

    /// Probe all enabled loaders against `data` and return sorted results.
    ///
    /// Results are sorted: lowest priority class first, highest confidence
    /// first within each class.
    ///
    /// # Panics
    /// Panics if the internal lock is poisoned.
    pub fn probe_all(&self, data: &[u8]) -> Vec<ProbeResult> {
        let mut results: Vec<ProbeResult> = {
            let entries = self.entries.read().unwrap();
            entries
                .iter()
                .filter(|e| e.enabled)
                .filter_map(|e| {
                    let conf = e.plugin.probe(data);
                    if conf == 0 {
                        None
                    } else {
                        Some(ProbeResult {
                            loader_name: e.plugin.name().to_string(),
                            confidence: conf,
                            priority: e.priority,
                        })
                    }
                })
                .collect()
        };
        results.sort_by_key(ProbeResult::rank_key);
        results
    }

    /// Select the best loader for `data`, or return `None` if no loader matches.
    ///
    /// # Panics
    /// Panics if the internal lock is poisoned.
    pub fn auto_select(&self, data: &[u8]) -> Option<Arc<dyn LoaderPlugin>> {
        let best_name = {
            let results = self.probe_all(data);
            results.into_iter().next().map(|r| r.loader_name)
        };

        if let Some(name) = best_name {
            let mut entries = self.entries.write().unwrap();
            if let Some(e) = entries.iter_mut().find(|e| e.plugin.name() == name) {
                e.select_count += 1;
                return Some(Arc::clone(&e.plugin));
            }
        }
        None
    }

    /// Record a successful load for loader `name`.
    ///
    /// # Panics
    /// Panics if the internal lock is poisoned.
    pub fn record_success(&self, name: &str) {
        let mut entries = self.entries.write().unwrap();
        if let Some(e) = entries.iter_mut().find(|e| e.plugin.name() == name) {
            e.success_count += 1;
        }
    }

    /// Record a failed load for loader `name`.
    ///
    /// # Panics
    /// Panics if the internal lock is poisoned.
    pub fn record_failure(&self, name: &str) {
        let mut entries = self.entries.write().unwrap();
        if let Some(e) = entries.iter_mut().find(|e| e.plugin.name() == name) {
            e.failure_count += 1;
        }
    }

    /// Find a loader by exact name.
    ///
    /// # Panics
    /// Panics if the internal lock is poisoned.
    pub fn find(&self, name: &str) -> Option<Arc<dyn LoaderPlugin>> {
        let entries = self.entries.read().unwrap();
        entries
            .iter()
            .find(|e| e.plugin.name() == name)
            .map(|e| Arc::clone(&e.plugin))
    }

    /// Return all loaders that support the given capability.
    ///
    /// # Panics
    /// Panics if the internal lock is poisoned.
    pub fn with_capability(&self, cap: LoaderCapability) -> Vec<Arc<dyn LoaderPlugin>> {
        let entries = self.entries.read().unwrap();
        entries
            .iter()
            .filter(|e| e.enabled && e.plugin.capabilities().contains(&cap))
            .map(|e| Arc::clone(&e.plugin))
            .collect()
    }

    /// Return all loaders that handle the given format.
    ///
    /// # Panics
    /// Panics if the internal lock is poisoned.
    pub fn for_format(&self, tag: &FormatTag) -> Vec<Arc<dyn LoaderPlugin>> {
        let entries = self.entries.read().unwrap();
        entries
            .iter()
            .filter(|e| e.enabled && e.plugin.formats().contains(tag))
            .map(|e| Arc::clone(&e.plugin))
            .collect()
    }

    /// Number of registered loaders.
    ///
    /// # Panics
    /// Panics if the internal lock is poisoned.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.read().unwrap().len()
    }

    /// Returns `true` if no loaders are registered.
    ///
    /// # Panics
    /// Panics if the internal lock is poisoned.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.read().unwrap().is_empty()
    }

    /// Return names of all registered loaders.
    ///
    /// # Panics
    /// Panics if the internal lock is poisoned.
    pub fn names(&self) -> Vec<String> {
        self.entries
            .read()
            .unwrap()
            .iter()
            .map(|e| e.plugin.name().to_string())
            .collect()
    }

    /// Compute aggregate statistics.
    ///
    /// # Panics
    /// Panics if the internal lock is poisoned.
    pub fn stats(&self) -> RegistryStats {
        let entries = self.entries.read().unwrap();
        let mut stats = RegistryStats {
            total_loaders: entries.len(),
            enabled_loaders: entries.iter().filter(|e| e.enabled).count(),
            ..Default::default()
        };
        for entry in entries.iter() {
            stats.total_selects += entry.select_count;
            stats.total_successes += entry.success_count;
            stats.total_failures += entry.failure_count;
            for fmt in entry.plugin.formats() {
                *stats.format_counts.entry(fmt.to_string()).or_insert(0) += 1;
            }
        }
        drop(entries);
        stats
    }

    /// Return per-loader statistics sorted by select count descending.
    ///
    /// # Panics
    /// Panics if the internal lock is poisoned.
    pub fn loader_stats(&self) -> Vec<LoaderStat> {
        let mut v: Vec<LoaderStat> = {
            let entries = self.entries.read().unwrap();
            entries
                .iter()
                .map(|e| LoaderStat {
                    name: e.plugin.name().to_string(),
                    priority: e.priority,
                    enabled: e.enabled,
                    select_count: e.select_count,
                    success_count: e.success_count,
                    failure_count: e.failure_count,
                })
                .collect()
        };
        v.sort_by(|a, b| b.select_count.cmp(&a.select_count));
        v
    }
}

impl fmt::Debug for PluginRegistry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let count = self.len();
        f.debug_struct("PluginRegistry")
            .field("loader_count", &count)
            .finish_non_exhaustive()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// LoaderStat
// ─────────────────────────────────────────────────────────────────────────────

/// Per-loader statistics snapshot.
#[derive(Debug, Clone)]
pub struct LoaderStat {
    pub name: String,
    pub priority: LoaderPriority,
    pub enabled: bool,
    pub select_count: u64,
    pub success_count: u64,
    pub failure_count: u64,
}

impl LoaderStat {
    #[must_use] 
    pub fn success_rate(&self) -> f64 {
        let total = self.success_count + self.failure_count;
        if total == 0 { 0.0 } else { f64::from(u32::try_from(self.success_count).unwrap_or(u32::MAX)) / f64::from(u32::try_from(total).unwrap_or(u32::MAX)) }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Concrete stub plugins for testing
// ─────────────────────────────────────────────────────────────────────────────

/// A stub loader plugin for testing.
#[derive(Debug)]
pub struct StubPlugin {
    pub name: String,
    pub description: String,
    pub formats: Vec<FormatTag>,
    pub extensions: Vec<&'static str>,
    pub capabilities: Vec<LoaderCapability>,
    pub magic: Vec<u8>,
    pub probe_score: u8,
}

impl StubPlugin {
    pub fn new(name: impl Into<String>, magic: Vec<u8>, probe_score: u8) -> Self {
        Self {
            name: name.into(),
            description: String::new(),
            formats: vec![],
            extensions: vec![],
            capabilities: vec![],
            magic,
            probe_score,
        }
    }

    #[must_use] 
    pub fn with_format(mut self, tag: FormatTag) -> Self {
        self.formats.push(tag);
        self
    }

    #[must_use] 
    pub fn with_capability(mut self, cap: LoaderCapability) -> Self {
        self.capabilities.push(cap);
        self
    }
}

impl LoaderPlugin for StubPlugin {
    fn name(&self) -> &str { &self.name }
    fn description(&self) -> &str { &self.description }
    fn formats(&self) -> &[FormatTag] { &self.formats }
    fn extensions(&self) -> &[&str] { &self.extensions }
    fn probe(&self, data: &[u8]) -> u8 {
        if !self.magic.is_empty() && data.starts_with(&self.magic) {
            self.probe_score
        } else {
            0
        }
    }
    fn capabilities(&self) -> &[LoaderCapability] { &self.capabilities }
}

// ─────────────────────────────────────────────────────────────────────────────
// RegistryBuilder
// ─────────────────────────────────────────────────────────────────────────────

/// Fluent builder for constructing a `PluginRegistry`.
pub struct RegistryBuilder {
    registry: PluginRegistry,
}

impl RegistryBuilder {
    #[must_use] 
    pub const fn new() -> Self {
        Self { registry: PluginRegistry::new() }
    }

    /// Add a plugin to the registry being built.
    ///
    /// # Panics
    /// Panics if the internal lock is poisoned.
    #[must_use]
    pub fn add(self, plugin: impl LoaderPlugin + 'static, priority: LoaderPriority) -> Self {
        self.registry.register(Arc::new(plugin), priority);
        self
    }

    pub fn build(self) -> PluginRegistry {
        self.registry
    }
}

impl Default for RegistryBuilder {
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

    fn elf_plugin() -> Arc<dyn LoaderPlugin> {
        Arc::new(
            StubPlugin::new("elf", b"\x7fELF".to_vec(), 255)
                .with_format(FormatTag::Elf)
                .with_capability(LoaderCapability::ReadSections)
                .with_capability(LoaderCapability::ReadSymbols),
        )
    }

    fn pe_plugin() -> Arc<dyn LoaderPlugin> {
        Arc::new(
            StubPlugin::new("pe", b"MZ".to_vec(), 200)
                .with_format(FormatTag::Pe)
                .with_capability(LoaderCapability::ReadImports),
        )
    }

    fn elf_data() -> Vec<u8> {
        let mut d = b"\x7fELF\x02\x01\x01\x00".to_vec();
        d.extend_from_slice(&[0u8; 64]);
        d
    }

    fn _pe_data() -> Vec<u8> {
        let mut d = b"MZ\x90\x00".to_vec();
        d.extend_from_slice(&[0u8; 64]);
        d
    }

    #[test]
    fn test_register_and_find() {
        let reg = PluginRegistry::new();
        reg.register(elf_plugin(), LoaderPriority::Definitive);
        let found = reg.find("elf");
        assert!(found.is_some());
        assert_eq!(found.unwrap().name(), "elf");
    }

    #[test]
    fn test_no_duplicate_registration() {
        let reg = PluginRegistry::new();
        reg.register(elf_plugin(), LoaderPriority::Definitive);
        reg.register(elf_plugin(), LoaderPriority::High); // duplicate
        assert_eq!(reg.len(), 1);
    }

    #[test]
    fn test_probe_all_elf() {
        let reg = PluginRegistry::new();
        reg.register(elf_plugin(), LoaderPriority::Definitive);
        reg.register(pe_plugin(), LoaderPriority::High);
        let results = reg.probe_all(&elf_data());
        assert!(!results.is_empty());
        assert_eq!(results[0].loader_name, "elf");
        assert_eq!(results[0].confidence, 255);
    }

    #[test]
    fn test_auto_select_elf() {
        let reg = PluginRegistry::new();
        reg.register(elf_plugin(), LoaderPriority::Definitive);
        reg.register(pe_plugin(), LoaderPriority::High);
        let selected = reg.auto_select(&elf_data());
        assert!(selected.is_some());
        assert_eq!(selected.unwrap().name(), "elf");
    }

    #[test]
    fn test_auto_select_none() {
        let reg = PluginRegistry::new();
        reg.register(elf_plugin(), LoaderPriority::Definitive);
        // Data that matches nothing.
        let selected = reg.auto_select(&[0xDE, 0xAD, 0xBE, 0xEF]);
        assert!(selected.is_none());
    }

    #[test]
    fn test_select_count_incremented() {
        let reg = PluginRegistry::new();
        reg.register(elf_plugin(), LoaderPriority::Definitive);
        reg.auto_select(&elf_data());
        reg.auto_select(&elf_data());
        let stats = reg.loader_stats();
        let elf_stat = stats.iter().find(|s| s.name == "elf").unwrap();
        assert_eq!(elf_stat.select_count, 2);
    }

    #[test]
    fn test_record_success_failure() {
        let reg = PluginRegistry::new();
        reg.register(elf_plugin(), LoaderPriority::Definitive);
        reg.record_success("elf");
        reg.record_success("elf");
        reg.record_failure("elf");
        let stats = reg.loader_stats();
        let s = stats.iter().find(|s| s.name == "elf").unwrap();
        assert_eq!(s.success_count, 2);
        assert_eq!(s.failure_count, 1);
        assert!((s.success_rate() - 2.0 / 3.0).abs() < 0.01);
    }

    #[test]
    fn test_with_capability() {
        let reg = PluginRegistry::new();
        reg.register(elf_plugin(), LoaderPriority::Definitive);
        reg.register(pe_plugin(), LoaderPriority::High);
        let sym_loaders = reg.with_capability(LoaderCapability::ReadSymbols);
        assert_eq!(sym_loaders.len(), 1);
        assert_eq!(sym_loaders[0].name(), "elf");
    }

    #[test]
    fn test_for_format() {
        let reg = PluginRegistry::new();
        reg.register(elf_plugin(), LoaderPriority::Definitive);
        reg.register(pe_plugin(), LoaderPriority::High);
        let elf_loaders = reg.for_format(&FormatTag::Elf);
        assert_eq!(elf_loaders.len(), 1);
    }

    #[test]
    fn test_enable_disable() {
        let reg = PluginRegistry::new();
        reg.register(elf_plugin(), LoaderPriority::Definitive);
        reg.set_enabled("elf", false);
        let results = reg.probe_all(&elf_data());
        assert!(results.is_empty());
        reg.set_enabled("elf", true);
        let results = reg.probe_all(&elf_data());
        assert!(!results.is_empty());
    }

    #[test]
    fn test_unregister() {
        let reg = PluginRegistry::new();
        reg.register(elf_plugin(), LoaderPriority::Definitive);
        assert!(reg.unregister("elf"));
        assert_eq!(reg.len(), 0);
        assert!(!reg.unregister("elf")); // not found
    }

    #[test]
    fn test_stats() {
        let reg = PluginRegistry::new();
        reg.register(elf_plugin(), LoaderPriority::Definitive);
        reg.register(pe_plugin(), LoaderPriority::High);
        let stats = reg.stats();
        assert_eq!(stats.total_loaders, 2);
        assert_eq!(stats.enabled_loaders, 2);
    }

    #[test]
    fn test_registry_builder() {
        let reg = RegistryBuilder::new()
            .add(StubPlugin::new("elf", b"\x7fELF".to_vec(), 255), LoaderPriority::Definitive)
            .add(StubPlugin::new("pe", b"MZ".to_vec(), 200), LoaderPriority::High)
            .build();
        assert_eq!(reg.len(), 2);
    }

    #[test]
    fn test_loader_priority_ordering() {
        assert!(LoaderPriority::Definitive < LoaderPriority::High);
        assert!(LoaderPriority::High < LoaderPriority::Medium);
        assert!(LoaderPriority::Medium < LoaderPriority::Low);
        assert!(LoaderPriority::Low < LoaderPriority::Fallback);
    }

    #[test]
    fn test_names() {
        let reg = PluginRegistry::new();
        reg.register(elf_plugin(), LoaderPriority::Definitive);
        reg.register(pe_plugin(), LoaderPriority::High);
        let names = reg.names();
        assert!(names.contains(&"elf".to_string()));
        assert!(names.contains(&"pe".to_string()));
    }
}
