//! `probe_cascade` — Loader registry with confidence-cascade selection.
//!
//! This module provides [`LoaderCascadeRegistry`], which wraps a set of
//! [`MultiFormatLoader`] implementations and selects the best one using a
//! multi-round confidence cascade.
//!
//! # Algorithm
//!
//! 1. **Probe all** — every registered loader is asked for its confidence in
//!    `[0, 255]`.
//! 2. **Threshold gate** — loaders with confidence < 50 are eliminated.
//! 3. **Cascade select** — the highest-confidence survivor wins.  Ties are
//!    broken by registration order (first-registered wins).
//! 4. **Format voting** — when multiple loaders report the same confidence the
//!    most-voted format string is used for the diagnostic label.
//!
//! # Multi-architecture detection
//!
//! Fat/universal binaries (Mach-O fat, multi-arch archives) may cause more
//! than one arch-specific loader to report high confidence.  The cascade exposes
//! [`probe_all_arches`](LoaderCascadeRegistry::probe_all_arches) to surface all
//! candidates above the threshold, letting callers decide whether to fork
//! analysis into multiple views.

use std::collections::HashMap;
use std::sync::Arc;

use crate::MultiFormatLoader;

// ─── confidence threshold ─────────────────────────────────────────────────────

/// Minimum confidence required for a loader to participate in cascade
/// selection.  Loaders below this value are discarded.
pub const CASCADE_MIN_CONFIDENCE: u8 = 50;

// ─── ProbeResult ─────────────────────────────────────────────────────────────

/// The result of probing a single loader against an input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeResult {
    /// Loader name.
    pub loader_name: String,
    /// Confidence score in `[0, 255]`.
    pub confidence: u8,
    /// Format string reported by the loader.
    pub format_hint: String,
    /// Architecture tags detected by this loader (may be empty).
    pub arches: Vec<String>,
}

impl ProbeResult {
    /// Construct a `ProbeResult`.
    #[must_use]
    pub fn new(
        loader_name: impl Into<String>,
        confidence: u8,
        format_hint: impl Into<String>,
        arches: Vec<String>,
    ) -> Self {
        Self {
            loader_name: loader_name.into(),
            confidence,
            format_hint: format_hint.into(),
            arches,
        }
    }

    /// Return `true` if this result passes the cascade threshold.
    #[must_use]
    pub const fn passes_threshold(&self) -> bool {
        self.confidence >= CASCADE_MIN_CONFIDENCE
    }
}

impl std::fmt::Display for ProbeResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "[{:>3}] {:20} ({})",
            self.confidence, self.loader_name, self.format_hint
        )
    }
}

// ─── ArchDetection ────────────────────────────────────────────────────────────

/// Multi-architecture detection record produced by the cascade.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchDetection {
    /// Architecture tag, e.g. `"x86_64"`, `"arm64"`, `"wasm32"`.
    pub arch: String,
    /// The loader that detected this architecture.
    pub detected_by: String,
    /// Confidence score.
    pub confidence: u8,
}

impl ArchDetection {
    /// Construct an `ArchDetection`.
    #[must_use]
    pub fn new(arch: impl Into<String>, detected_by: impl Into<String>, confidence: u8) -> Self {
        Self {
            arch: arch.into(),
            detected_by: detected_by.into(),
            confidence,
        }
    }
}

// ─── CascadeEntry ────────────────────────────────────────────────────────────

/// Entry stored inside [`LoaderCascadeRegistry`].
struct CascadeEntry {
    loader: Arc<dyn MultiFormatLoader>,
    /// Optional architecture tag override (e.g. `"x86_64"`, `"arm64"`).
    arch_tag: Option<String>,
}

// ─── LoaderCascadeRegistry ───────────────────────────────────────────────────

/// Loader registry with confidence-cascade selection.
///
/// Wrap a set of [`MultiFormatLoader`] implementations.  Call
/// [`cascade_select`](Self::cascade_select) to obtain the single best loader
/// for a given byte slice, or [`probe_all`](Self::probe_all) for a ranked list
/// of all candidates.
///
/// # Thread safety
///
/// The registry is protected by a [`parking_lot::RwLock`].  Reads (probing)
/// take a read-lock and are fully concurrent; writes (registration) take an
/// exclusive write-lock.
pub struct LoaderCascadeRegistry {
    entries: parking_lot::RwLock<Vec<CascadeEntry>>,
}

impl std::fmt::Debug for LoaderCascadeRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let count = self.entries.read().len();
        f.debug_struct("LoaderCascadeRegistry")
            .field("registered", &count)
            .finish_non_exhaustive()
    }
}

impl Default for LoaderCascadeRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl LoaderCascadeRegistry {
    /// Create an empty registry.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            entries: parking_lot::RwLock::new(Vec::new()),
        }
    }

    /// Register a loader.  An optional `arch_tag` narrows the architecture
    /// reported by this loader (used by [`probe_all_arches`]).
    pub fn register<L: MultiFormatLoader + 'static>(&self, loader: L, arch_tag: Option<String>) {
        self.entries.write().push(CascadeEntry {
            loader: Arc::new(loader),
            arch_tag,
        });
    }

    /// Register a loader behind an existing `Arc`.
    pub fn register_arc(&self, loader: Arc<dyn MultiFormatLoader>, arch_tag: Option<String>) {
        self.entries.write().push(CascadeEntry { loader, arch_tag });
    }

    /// Probe all registered loaders against `data` and return the full list of
    /// [`ProbeResult`]s, sorted by confidence descending (only scores > 0 are
    /// included).
    ///
    /// This is the raw probe without the cascade threshold filter.
    #[must_use]
    pub fn probe_all_raw(&self, data: &[u8]) -> Vec<ProbeResult> {
        let mut results: Vec<ProbeResult> = {
            let entries = self.entries.read();
            entries
                .iter()
                .filter_map(|entry| {
                    let confidence = entry.loader.probe(data);
                    if confidence == 0 {
                        return None;
                    }
                    let arches: Vec<String> = entry.arch_tag.iter().cloned().collect();
                    Some(ProbeResult::new(
                        entry.loader.name(),
                        confidence,
                        entry.loader.description(),
                        arches,
                    ))
                })
                .collect()
        };
        results.sort_by(|a, b| b.confidence.cmp(&a.confidence));
        results
    }

    /// Probe all registered loaders against `data` and return only those with
    /// confidence ≥ [`CASCADE_MIN_CONFIDENCE`], sorted by confidence descending.
    #[must_use]
    pub fn probe_all(&self, data: &[u8]) -> Vec<ProbeResult> {
        self.probe_all_raw(data)
            .into_iter()
            .filter(ProbeResult::passes_threshold)
            .collect()
    }

    /// Run the cascade selection and return the best loader, or `None` when no
    /// loader passes the confidence threshold.
    ///
    /// Ties (equal confidence) are broken by registration order.
    #[must_use]
    pub fn cascade_select(&self, data: &[u8]) -> Option<Arc<dyn MultiFormatLoader>> {
        let mut best_confidence = CASCADE_MIN_CONFIDENCE.saturating_sub(1);
        let mut best: Option<Arc<dyn MultiFormatLoader>> = None;
        {
            let entries = self.entries.read();
            for entry in entries.iter() {
                let c = entry.loader.probe(data);
                if c > best_confidence {
                    best_confidence = c;
                    best = Some(Arc::clone(&entry.loader));
                }
            }
        }
        best
    }

    /// Return the voted format string for `data` — the format description
    /// reported by the highest-confidence loader(s), with ties resolved by
    /// majority vote among tied loaders.
    #[must_use]
    pub fn format_vote(&self, data: &[u8]) -> String {
        let raw = self.probe_all_raw(data);
        if raw.is_empty() {
            return "Unknown".to_owned();
        }

        let top_conf = raw[0].confidence;

        // Vote among format_hint strings of tied top-confidence loaders.
        let mut vote: HashMap<&str, usize> = HashMap::new();
        for r in raw.iter().filter(|r| r.confidence == top_conf) {
            *vote.entry(r.format_hint.as_str()).or_insert(0) += 1;
        }
        vote.into_iter()
            .max_by_key(|(_, c)| *c).map_or_else(|| "Unknown".to_owned(), |(fmt, _)| fmt.to_owned())
    }

    /// Return all distinct architecture detections for `data` — one per
    /// loader that passes the threshold and has an arch tag.
    #[must_use]
    pub fn probe_all_arches(&self, data: &[u8]) -> Vec<ArchDetection> {
        let mut arches: Vec<ArchDetection> = {
            let entries = self.entries.read();
            entries
                .iter()
                .filter_map(|entry| {
                    let confidence = entry.loader.probe(data);
                    if confidence < CASCADE_MIN_CONFIDENCE {
                        return None;
                    }
                    entry
                        .arch_tag
                        .as_ref()
                        .map(|arch| ArchDetection::new(arch.clone(), entry.loader.name(), confidence))
                })
                .collect()
        };
        // Deduplicate same arch / loader pairs.
        arches.sort_by(|a, b| b.confidence.cmp(&a.confidence).then(a.arch.cmp(&b.arch)));
        arches.dedup_by(|a, b| a.arch == b.arch && a.detected_by == b.detected_by);
        arches
    }

    /// Return the number of registered loaders.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.read().len()
    }

    /// Return `true` if no loaders are registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.read().is_empty()
    }

    /// Return all loader names in registration order.
    #[must_use]
    pub fn loader_names(&self) -> Vec<String> {
        self.entries
            .read()
            .iter()
            .map(|e| e.loader.name().to_owned())
            .collect()
    }

    /// Remove a loader by name.  Returns `true` if a loader was removed.
    pub fn remove(&self, name: &str) -> bool {
        let mut entries = self.entries.write();
        let before = entries.len();
        entries.retain(|e| e.loader.name() != name);
        entries.len() < before
    }

    /// Clear all registered loaders.
    pub fn clear(&self) {
        self.entries.write().clear();
    }
}

// ─── cascade_select free fn ──────────────────────────────────────────────────

/// Convenience free function: probe `loaders` against `data` and return the
/// highest-confidence loader whose score is ≥ `min_confidence`.
///
/// Loaders are expected to be `Arc<dyn MultiFormatLoader>`.
#[must_use]
pub fn cascade_select_from(
    loaders: &[Arc<dyn MultiFormatLoader>],
    data: &[u8],
    min_confidence: u8,
) -> Option<Arc<dyn MultiFormatLoader>> {
    loaders
        .iter()
        .filter_map(|l| {
            let c = l.probe(data);
            if c >= min_confidence {
                Some((Arc::clone(l), c))
            } else {
                None
            }
        })
        .max_by_key(|(_, c)| *c)
        .map(|(l, _)| l)
}

// ─── probe_all free fn ───────────────────────────────────────────────────────

/// Convenience free function: probe `loaders` against `data` and return a
/// sorted `Vec<(name, confidence)>` for all loaders with confidence > 0.
#[must_use]
pub fn probe_all(loaders: &[Arc<dyn MultiFormatLoader>], data: &[u8]) -> Vec<(String, u8)> {
    let mut results: Vec<(String, u8)> = loaders
        .iter()
        .map(|l| (l.name().to_owned(), l.probe(data)))
        .filter(|(_, c)| *c > 0)
        .collect();
    results.sort_by(|a, b| b.1.cmp(&a.1));
    results
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ElfStubLoader, PeStubLoader, WasmStubLoader};

    fn make_registry() -> LoaderCascadeRegistry {
        let r = LoaderCascadeRegistry::new();
        r.register(ElfStubLoader, Some("x86_64".to_owned()));
        r.register(PeStubLoader, Some("x86_64".to_owned()));
        r.register(WasmStubLoader, Some("wasm32".to_owned()));
        r
    }

    fn elf_bytes() -> Vec<u8> {
        let mut v = vec![0x7f, b'E', b'L', b'F', 2, 1, 1, 0];
        v.extend_from_slice(&[0u8; 56]);
        v
    }

    fn pe_bytes() -> Vec<u8> {
        let mut v = vec![b'M', b'Z'];
        v.extend_from_slice(&[0u8; 62]);
        v
    }

    fn wasm_bytes() -> Vec<u8> {
        let mut v = vec![0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00];
        v.extend_from_slice(&[0u8; 8]);
        v
    }

    #[test]
    fn test_cascade_registry_new_is_empty() {
        let r = LoaderCascadeRegistry::new();
        assert!(r.is_empty());
        assert_eq!(r.len(), 0);
    }

    #[test]
    fn test_register_increases_count() {
        let r = make_registry();
        assert_eq!(r.len(), 3);
    }

    #[test]
    fn test_probe_all_elf() {
        let r = make_registry();
        let results = r.probe_all(&elf_bytes());
        assert!(!results.is_empty());
        assert_eq!(results[0].loader_name, "elf");
        assert_eq!(results[0].confidence, 255);
    }

    #[test]
    fn test_probe_all_pe() {
        let r = make_registry();
        let results = r.probe_all(&pe_bytes());
        assert!(!results.is_empty());
        assert_eq!(results[0].loader_name, "pe");
    }

    #[test]
    fn test_probe_all_wasm() {
        let r = make_registry();
        let results = r.probe_all(&wasm_bytes());
        assert_eq!(results[0].loader_name, "wasm");
        assert_eq!(results[0].confidence, 255);
    }

    #[test]
    fn test_cascade_select_elf() {
        let r = make_registry();
        let loader = r.cascade_select(&elf_bytes()).unwrap();
        assert_eq!(loader.name(), "elf");
    }

    #[test]
    fn test_cascade_select_wasm() {
        let r = make_registry();
        let loader = r.cascade_select(&wasm_bytes()).unwrap();
        assert_eq!(loader.name(), "wasm");
    }

    #[test]
    fn test_cascade_select_none_for_unknown() {
        let r = LoaderCascadeRegistry::new();
        r.register(ElfStubLoader, None);
        let result = r.cascade_select(&[0xDE, 0xAD, 0xBE, 0xEF]);
        assert!(result.is_none());
    }

    #[test]
    fn test_probe_passes_threshold() {
        let pr = ProbeResult::new("test", 60, "TestFmt", vec![]);
        assert!(pr.passes_threshold());
    }

    #[test]
    fn test_probe_fails_threshold() {
        let pr = ProbeResult::new("test", 10, "TestFmt", vec![]);
        assert!(!pr.passes_threshold());
    }

    #[test]
    fn test_format_vote_elf() {
        let r = make_registry();
        let fmt = r.format_vote(&elf_bytes());
        assert!(!fmt.is_empty());
        assert_ne!(fmt, "Unknown");
    }

    #[test]
    fn test_format_vote_unknown() {
        let r = LoaderCascadeRegistry::new();
        let fmt = r.format_vote(&[0xDE, 0xAD]);
        assert_eq!(fmt, "Unknown");
    }

    #[test]
    fn test_probe_all_arches_elf() {
        let r = make_registry();
        let arches = r.probe_all_arches(&elf_bytes());
        assert!(!arches.is_empty());
        assert!(arches.iter().any(|a| a.arch == "x86_64"));
    }

    #[test]
    fn test_probe_all_arches_wasm() {
        let r = make_registry();
        let arches = r.probe_all_arches(&wasm_bytes());
        assert!(arches.iter().any(|a| a.arch == "wasm32"));
    }

    #[test]
    fn test_remove_loader() {
        let r = make_registry();
        assert!(r.remove("pe"));
        assert_eq!(r.len(), 2);
        assert!(!r.remove("nonexistent"));
    }

    #[test]
    fn test_clear() {
        let r = make_registry();
        r.clear();
        assert!(r.is_empty());
    }

    #[test]
    fn test_loader_names() {
        let r = make_registry();
        let names = r.loader_names();
        assert!(names.contains(&"elf".to_owned()));
        assert!(names.contains(&"wasm".to_owned()));
    }

    #[test]
    fn test_probe_all_raw_includes_low_confidence() {
        // The PeStubLoader gives confidence 200 for MZ magic.
        // ElfStubLoader gives 0 for PE bytes.
        let r = make_registry();
        let raw = r.probe_all_raw(&pe_bytes());
        // We should get at least PE loader.
        assert!(!raw.is_empty());
    }

    #[test]
    fn test_cascade_select_from_free_fn() {
        let loaders: Vec<Arc<dyn MultiFormatLoader>> =
            vec![Arc::new(ElfStubLoader), Arc::new(WasmStubLoader)];
        let selected = cascade_select_from(&loaders, &elf_bytes(), 50);
        assert!(selected.is_some());
        assert_eq!(selected.unwrap().name(), "elf");
    }

    #[test]
    fn test_probe_all_free_fn() {
        let loaders: Vec<Arc<dyn MultiFormatLoader>> =
            vec![Arc::new(ElfStubLoader), Arc::new(WasmStubLoader)];
        let results = probe_all(&loaders, &elf_bytes());
        assert!(!results.is_empty());
        assert_eq!(results[0].0, "elf");
    }

    #[test]
    fn test_probe_result_display() {
        let pr = ProbeResult::new("elf", 255, "ELF binary", vec!["x86_64".into()]);
        let s = pr.to_string();
        assert!(s.contains("255"));
        assert!(s.contains("elf"));
    }

    #[test]
    fn test_arch_detection_fields() {
        let ad = ArchDetection::new("arm64", "macho", 200);
        assert_eq!(ad.arch, "arm64");
        assert_eq!(ad.detected_by, "macho");
        assert_eq!(ad.confidence, 200);
    }

    #[test]
    fn test_registry_debug() {
        let r = make_registry();
        let s = format!("{r:?}");
        assert!(s.contains("LoaderCascadeRegistry"));
    }

    #[test]
    fn test_probe_all_sorted_descending() {
        let r = make_registry();
        let results = r.probe_all_raw(&elf_bytes());
        for w in results.windows(2) {
            assert!(w[0].confidence >= w[1].confidence);
        }
    }

    #[test]
    fn test_register_arc() {
        let r = LoaderCascadeRegistry::new();
        r.register_arc(Arc::new(ElfStubLoader), Some("x86_64".to_owned()));
        assert_eq!(r.len(), 1);
    }
}
