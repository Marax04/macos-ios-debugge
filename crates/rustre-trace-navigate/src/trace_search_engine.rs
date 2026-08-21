//! Execution trace search engine.
//!
//! Full-text / pattern search over a recorded execution trace.  Builds
//! secondary indexes for fast address and mnemonic lookups, supports byte
//! pattern matching, register-value matching, and API-call name matching.

use std::collections::HashMap;

// ---------------------------------------------------------------------------
// TraceEntry
// ---------------------------------------------------------------------------

/// A single recorded execution event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceEntry {
    /// High-resolution timestamp in nanoseconds.
    pub timestamp_ns: u64,
    /// OS thread identifier.
    pub thread_id: u32,
    /// Instruction address.
    pub address: u64,
    /// Disassembly text (e.g. `"mov eax, 1"`).
    pub disasm: String,
    /// Raw instruction bytes (up to 15 bytes).
    pub bytes: Vec<u8>,
    /// Register snapshot at this point (`reg_name` → value).
    pub registers: HashMap<String, u64>,
}

impl TraceEntry {
    /// Create a minimal `TraceEntry`.
    #[must_use]
    pub fn new(timestamp_ns: u64, thread_id: u32, address: u64, disasm: &str) -> Self {
        Self {
            timestamp_ns,
            thread_id,
            address,
            disasm: disasm.to_owned(),
            bytes: Vec::new(),
            registers: HashMap::new(),
        }
    }

    /// Return the mnemonic (first whitespace-separated token of `disasm`).
    #[must_use]
    pub fn mnemonic(&self) -> &str {
        self.disasm.split_whitespace().next().unwrap_or("")
    }

    /// Return `true` if this entry is a CALL instruction.
    #[must_use]
    pub fn is_call(&self) -> bool {
        let m = self.mnemonic().to_lowercase();
        m == "call" || m == "callq"
    }

    /// Return `true` if this entry is a RET instruction.
    #[must_use]
    pub fn is_ret(&self) -> bool {
        let m = self.mnemonic().to_lowercase();
        m == "ret" || m == "retq" || m == "retn"
    }
}

// ---------------------------------------------------------------------------
// SearchPattern
// ---------------------------------------------------------------------------

/// A single pattern element used in a `SearchQuery`.
#[derive(Debug, Clone)]
pub enum SearchPattern {
    /// Match a specific instruction address.
    Address(u64),
    /// Match any instruction whose mnemonic equals this string (case-insensitive).
    Mnemonic(String),
    /// Match when a specific register holds a specific value.
    Register { reg: String, value: u64 },
    /// Match when the disasm contains an API call by name.
    ApiCall(String),
    /// Match when the raw instruction bytes start with (or contain) this sequence.
    BytePattern(Vec<u8>),
}

impl SearchPattern {
    /// Returns `true` if this pattern matches the given `TraceEntry`.
    #[must_use]
    pub fn matches(&self, entry: &TraceEntry) -> bool {
        match self {
            Self::Address(a) => entry.address == *a,
            Self::Mnemonic(m) => {
                entry.mnemonic().eq_ignore_ascii_case(m)
            }
            Self::Register { reg, value } => {
                entry.registers.get(reg).copied() == Some(*value)
            }
            Self::ApiCall(api) => {
                entry.disasm.to_lowercase().contains(&api.to_lowercase())
            }
            Self::BytePattern(needle) => {
                contains_subslice(&entry.bytes, needle)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// SearchQuery
// ---------------------------------------------------------------------------

/// Specifies what to search for in the trace.
#[derive(Debug, Clone)]
pub struct SearchQuery {
    /// All patterns must match (AND semantics across patterns).
    pub patterns: Vec<SearchPattern>,
    /// Restrict search to entries within this timestamp range.
    pub time_range: Option<(u64, u64)>,
    /// Restrict search to a specific thread ID.
    pub thread_filter: Option<u32>,
    /// Maximum number of results to return.
    pub max_results: u32,
}

impl Default for SearchQuery {
    fn default() -> Self {
        Self {
            patterns: Vec::new(),
            time_range: None,
            thread_filter: None,
            max_results: 100,
        }
    }
}

impl SearchQuery {
    /// Create a query that matches a single address.
    #[must_use]
    pub fn for_address(address: u64) -> Self {
        Self {
            patterns: vec![SearchPattern::Address(address)],
            ..Default::default()
        }
    }

    /// Create a query that matches a mnemonic.
    #[must_use]
    pub fn for_mnemonic(mnemonic: &str) -> Self {
        Self {
            patterns: vec![SearchPattern::Mnemonic(mnemonic.to_owned())],
            ..Default::default()
        }
    }

    /// Returns `true` if `entry` passes all filters in this query.
    #[must_use]
    pub fn entry_passes_filters(&self, entry: &TraceEntry) -> bool {
        if let Some(tid) = self.thread_filter
            && entry.thread_id != tid {
                return false;
            }
        if let Some((lo, hi)) = self.time_range
            && (entry.timestamp_ns < lo || entry.timestamp_ns > hi) {
                return false;
            }
        self.patterns.iter().all(|p| p.matches(entry))
    }
}

// ---------------------------------------------------------------------------
// SearchResult
// ---------------------------------------------------------------------------

/// A single hit returned by `TraceSearchEngine::search`.
#[derive(Debug, Clone)]
pub struct SearchResult {
    /// Timestamp of the matching entry.
    pub timestamp_ns: u64,
    /// Thread ID.
    pub thread_id: u32,
    /// Instruction address.
    pub address: u64,
    /// Indices into `query.patterns` that matched this entry.
    pub matched_patterns: Vec<usize>,
    /// Surrounding trace entries (context window).
    pub context: Vec<TraceEntry>,
    /// Index of the matching entry in the original trace.
    pub trace_index: usize,
}

// ---------------------------------------------------------------------------
// TraceSearchEngine
// ---------------------------------------------------------------------------

/// Indexes a trace and evaluates search queries against it.
///
/// Builds secondary indexes on first use for fast address and mnemonic lookups.
pub struct TraceSearchEngine {
    /// The trace entries.
    entries: Vec<TraceEntry>,
    /// Index: address → list of entry indices.
    address_index: HashMap<u64, Vec<usize>>,
    /// Index: lowercase mnemonic → list of entry indices.
    mnemonic_index: HashMap<String, Vec<usize>>,
    /// How many entries to include before/after a match as context.
    pub context_window: usize,
}

impl TraceSearchEngine {
    /// Create a new engine and build indexes for the given trace.
    #[must_use]
    pub fn new(entries: Vec<TraceEntry>) -> Self {
        let mut engine = Self {
            entries,
            address_index: HashMap::new(),
            mnemonic_index: HashMap::new(),
            context_window: 3,
        };
        engine.build_address_index();
        engine.build_mnemonic_index();
        engine
    }

    /// Create an empty engine.
    #[must_use]
    pub fn empty() -> Self {
        Self::new(vec![])
    }

    /// Replace the trace and rebuild indexes.
    pub fn load_trace(&mut self, entries: Vec<TraceEntry>) {
        self.entries = entries;
        self.address_index.clear();
        self.mnemonic_index.clear();
        self.build_address_index();
        self.build_mnemonic_index();
    }

    /// Return the number of entries in the trace.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` if the trace is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Build the address → index mapping.
    pub fn build_address_index(&mut self) {
        self.address_index.clear();
        for (i, entry) in self.entries.iter().enumerate() {
            self.address_index.entry(entry.address).or_default().push(i);
        }
    }

    /// Build the mnemonic → index mapping.
    pub fn build_mnemonic_index(&mut self) {
        self.mnemonic_index.clear();
        for (i, entry) in self.entries.iter().enumerate() {
            let mnemonic = entry.mnemonic().to_lowercase();
            self.mnemonic_index.entry(mnemonic).or_default().push(i);
        }
    }

    // ── search ─────────────────────────────────────────────────────────────

    /// Execute a search query and return matching results.
    ///
    /// Uses the secondary indexes when the query contains address or mnemonic
    /// patterns to avoid scanning the full trace.
    #[must_use]
    pub fn search(&self, query: &SearchQuery) -> Vec<SearchResult> {
        if query.patterns.is_empty() {
            return Vec::new();
        }

        let candidates = self.candidate_indices(query);
        let mut results: Vec<SearchResult> = Vec::new();

        for idx in candidates {
            if results.len() >= query.max_results as usize {
                break;
            }
            let entry = &self.entries[idx];
            if !query.entry_passes_filters(entry) {
                continue;
            }
            let matched_patterns: Vec<usize> = query
                .patterns
                .iter()
                .enumerate()
                .filter(|(_, p)| p.matches(entry))
                .map(|(i, _)| i)
                .collect();

            if matched_patterns.len() == query.patterns.len() {
                let context = self.extract_context(idx);
                results.push(SearchResult {
                    timestamp_ns: entry.timestamp_ns,
                    thread_id: entry.thread_id,
                    address: entry.address,
                    matched_patterns,
                    context,
                    trace_index: idx,
                });
            }
        }
        results
    }

    /// Search for all occurrences of an API call by name.
    #[must_use]
    pub fn search_api_calls(&self, api_name: &str, max_results: u32) -> Vec<SearchResult> {
        let query = SearchQuery {
            patterns: vec![SearchPattern::ApiCall(api_name.to_owned())],
            max_results,
            ..Default::default()
        };
        self.search(&query)
    }

    /// Search for a byte pattern anywhere in the recorded instruction bytes.
    #[must_use]
    pub fn search_byte_pattern(&self, pattern: &[u8], max_results: u32) -> Vec<SearchResult> {
        let query = SearchQuery {
            patterns: vec![SearchPattern::BytePattern(pattern.to_vec())],
            max_results,
            ..Default::default()
        };
        self.search(&query)
    }

    /// Return all indices of entries at a specific address.
    pub fn indices_at_address(&self, address: u64) -> &[usize] {
        self.address_index.get(&address).map_or(&[][..], std::vec::Vec::as_slice)
    }

    /// Return all indices of entries with the given mnemonic.
    pub fn indices_with_mnemonic(&self, mnemonic: &str) -> &[usize] {
        self.mnemonic_index
            .get(&mnemonic.to_lowercase())
            .map_or(&[][..], std::vec::Vec::as_slice)
    }

    /// Return the top N most-executed addresses sorted by hit count (descending).
    #[must_use]
    pub fn top_addresses(&self, n: usize) -> Vec<(u64, usize)> {
        let mut pairs: Vec<(u64, usize)> = self
            .address_index
            .iter()
            .map(|(addr, indices)| (*addr, indices.len()))
            .collect();
        pairs.sort_by_key(|b| std::cmp::Reverse(b.1));
        pairs.truncate(n);
        pairs
    }

    /// Return the mnemonic frequency distribution, sorted descending.
    #[must_use]
    pub fn mnemonic_frequency(&self) -> Vec<(String, usize)> {
        let mut pairs: Vec<(String, usize)> = self
            .mnemonic_index
            .iter()
            .map(|(m, v)| (m.clone(), v.len()))
            .collect();
        pairs.sort_by_key(|b| std::cmp::Reverse(b.1));
        pairs
    }

    /// Returns a reference to the entry at `index`, if it exists.
    #[must_use]
    pub fn entry_at(&self, index: usize) -> Option<&TraceEntry> {
        self.entries.get(index)
    }

    // ── internal helpers ───────────────────────────────────────────────────

    /// Collect candidate indices to check.
    ///
    /// Uses the address index when any `Address` patterns are present;
    /// falls back to the mnemonic index for `Mnemonic` patterns; otherwise
    /// iterates all entries.
    fn candidate_indices(&self, query: &SearchQuery) -> Vec<usize> {
        // Try address index first
        for p in &query.patterns {
            if let SearchPattern::Address(addr) = p {
                if let Some(idxs) = self.address_index.get(addr) {
                    return idxs.clone();
                }
                return Vec::new();
            }
        }
        // Try mnemonic index
        for p in &query.patterns {
            if let SearchPattern::Mnemonic(m) = p {
                if let Some(idxs) = self.mnemonic_index.get(&m.to_lowercase()) {
                    return idxs.clone();
                }
                return Vec::new();
            }
        }
        // Full scan
        (0..self.entries.len()).collect()
    }

    fn extract_context(&self, idx: usize) -> Vec<TraceEntry> {
        let start = idx.saturating_sub(self.context_window);
        let end = (idx + self.context_window + 1).min(self.entries.len());
        self.entries[start..end].to_vec()
    }
}

// ---------------------------------------------------------------------------
// Byte pattern helper
// ---------------------------------------------------------------------------

fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    if needle.len() > haystack.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_entry(ts: u64, tid: u32, addr: u64, disasm: &str) -> TraceEntry {
        TraceEntry::new(ts, tid, addr, disasm)
    }

    fn sample_trace() -> Vec<TraceEntry> {
        vec![
            make_entry(100, 1, 0x1000, "push rbp"),
            make_entry(200, 1, 0x1001, "mov rbp, rsp"),
            make_entry(300, 1, 0x1004, "call VirtualAlloc"),
            make_entry(400, 1, 0x2000, "mov eax, 1"),
            make_entry(500, 2, 0x1000, "push rbp"),
            make_entry(600, 2, 0x3000, "ret"),
            make_entry(700, 1, 0x1000, "push rbp"),
        ]
    }

    #[test]
    fn test_mnemonic_extraction() {
        let e = make_entry(0, 0, 0, "mov eax, 1");
        assert_eq!(e.mnemonic(), "mov");
    }

    #[test]
    fn test_is_call() {
        let e = make_entry(0, 0, 0, "call VirtualAlloc");
        assert!(e.is_call());
    }

    #[test]
    fn test_is_ret() {
        let e = make_entry(0, 0, 0, "ret");
        assert!(e.is_ret());
    }

    #[test]
    fn test_engine_len() {
        let engine = TraceSearchEngine::new(sample_trace());
        assert_eq!(engine.len(), 7);
    }

    #[test]
    fn test_address_index_built() {
        let engine = TraceSearchEngine::new(sample_trace());
        let idxs = engine.indices_at_address(0x1000);
        assert_eq!(idxs.len(), 3); // entries 0, 4, 6
    }

    #[test]
    fn test_mnemonic_index_built() {
        let engine = TraceSearchEngine::new(sample_trace());
        let idxs = engine.indices_with_mnemonic("push");
        assert_eq!(idxs.len(), 3);
    }

    #[test]
    fn test_search_address() {
        let engine = TraceSearchEngine::new(sample_trace());
        let q = SearchQuery::for_address(0x2000);
        let results = engine.search(&q);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].address, 0x2000);
    }

    #[test]
    fn test_search_mnemonic() {
        let engine = TraceSearchEngine::new(sample_trace());
        let q = SearchQuery::for_mnemonic("push");
        let results = engine.search(&q);
        assert_eq!(results.len(), 3);
    }

    #[test]
    fn test_search_thread_filter() {
        let engine = TraceSearchEngine::new(sample_trace());
        let q = SearchQuery {
            patterns: vec![SearchPattern::Mnemonic("push".to_owned())],
            thread_filter: Some(2),
            max_results: 100,
            ..Default::default()
        };
        let results = engine.search(&q);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].thread_id, 2);
    }

    #[test]
    fn test_search_time_range() {
        let engine = TraceSearchEngine::new(sample_trace());
        let q = SearchQuery {
            patterns: vec![SearchPattern::Mnemonic("push".to_owned())],
            time_range: Some((100, 300)),
            max_results: 100,
            ..Default::default()
        };
        let results = engine.search(&q);
        assert_eq!(results.len(), 1); // only ts=100 is within range
    }

    #[test]
    fn test_search_api_call() {
        let engine = TraceSearchEngine::new(sample_trace());
        let results = engine.search_api_calls("VirtualAlloc", 10);
        assert_eq!(results.len(), 1);
        assert!(results[0].address == 0x1004);
    }

    #[test]
    fn test_search_byte_pattern_empty_bytes() {
        let engine = TraceSearchEngine::new(sample_trace());
        // Entries have no bytes set, so byte pattern search should return nothing
        let results = engine.search_byte_pattern(&[0x55, 0x48], 10);
        assert_eq!(results.len(), 0);
    }

    #[test]
    fn test_search_byte_pattern_with_bytes() {
        let mut entries = sample_trace();
        entries[0].bytes = vec![0x55, 0x48, 0x89, 0xe5];
        let engine = TraceSearchEngine::new(entries);
        let results = engine.search_byte_pattern(&[0x55, 0x48], 10);
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn test_top_addresses() {
        let engine = TraceSearchEngine::new(sample_trace());
        let top = engine.top_addresses(3);
        assert!(!top.is_empty());
        assert_eq!(top[0].0, 0x1000); // most visited
        assert_eq!(top[0].1, 3);
    }

    #[test]
    fn test_mnemonic_frequency() {
        let engine = TraceSearchEngine::new(sample_trace());
        let freq = engine.mnemonic_frequency();
        assert!(!freq.is_empty());
        assert_eq!(freq[0].0, "push"); // push appears 3 times
    }

    #[test]
    fn test_search_max_results() {
        let engine = TraceSearchEngine::new(sample_trace());
        let q = SearchQuery {
            patterns: vec![SearchPattern::Mnemonic("push".to_owned())],
            max_results: 1,
            ..Default::default()
        };
        let results = engine.search(&q);
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn test_context_window() {
        let engine = TraceSearchEngine::new(sample_trace());
        let q = SearchQuery::for_address(0x1004);
        let results = engine.search(&q);
        assert!(!results.is_empty());
        // Context window = 3 default
        assert!(results[0].context.len() <= 7);
        assert!(!results[0].context.is_empty());
    }

    #[test]
    fn test_empty_query_returns_nothing() {
        let engine = TraceSearchEngine::new(sample_trace());
        let q = SearchQuery::default();
        let results = engine.search(&q);
        assert!(results.is_empty());
    }

    #[test]
    fn test_contains_subslice() {
        assert!(contains_subslice(&[1, 2, 3, 4], &[2, 3]));
        assert!(!contains_subslice(&[1, 2, 3], &[4, 5]));
        assert!(contains_subslice(&[1], &[]));
    }
}
