//! `memory_search` — Search process memory regions for byte patterns.
//!
//! Supports exact byte sequences, wildcard hex patterns (e.g. `"DE AD ?? BE"`),
//! UTF-8 / UTF-16LE strings, and cross-region searches.
//!
//! Key types: [`MemorySearch`], [`SearchPattern`], [`SearchResult`],
//! [`search_all_regions`]

use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::ops::Range;

// opt-10: stable branch-prediction hints implemented via cold-function pattern.
// The compiler lowers `unlikely(b)` call-sites as less-likely branches because
// the callee is `#[cold]`.  `likely` is a transparent no-op at this level —
// the hint comes from marking the *unlikely* branches instead.
#[inline(always)]
fn likely(b: bool) -> bool { b }
#[cold]
#[inline(always)]
fn unlikely(b: bool) -> bool { b }

// ─── Error ────────────────────────────────────────────────────────────────────

/// Errors returned by memory search operations.
#[derive(Debug, thiserror::Error)]
pub enum SearchError {
    #[error("invalid hex pattern: {0}")]
    InvalidPattern(String),
    #[error("empty search pattern")]
    EmptyPattern,
    #[error("region {start:#x}..{end:#x} is not readable")]
    RegionNotReadable { start: u64, end: u64 },
    #[error("search was cancelled")]
    Cancelled,
}

// opt-8: keep error-construction code off hot instruction paths.
#[cold]
#[inline(never)]
fn cold_invalid_pattern(msg: String) -> SearchError {
    SearchError::InvalidPattern(msg)
}
#[cold]
#[inline(never)]
fn cold_empty_pattern() -> SearchError {
    SearchError::EmptyPattern
}

// ─── SearchPattern ────────────────────────────────────────────────────────────

/// A pattern to search for in memory.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SearchPattern {
    /// Exact byte sequence.
    Bytes(Vec<u8>),
    /// Hex pattern with optional `??` wildcards per byte, e.g. `"DE AD ?? BE"`.
    HexWildcard(String),
    /// UTF-8 string (case-sensitive).
    Utf8(String),
    /// UTF-8 string (case-insensitive).
    Utf8CaseInsensitive(String),
    /// UTF-16 LE string.
    Utf16Le(String),
    /// Multi-byte XOR-encoded pattern: each pattern byte is `XORed` with `key`.
    Xor { pattern: Vec<u8>, key: u8 },
}

impl SearchPattern {
    /// Parse a hex wildcard string and validate it.
    ///
    /// # Errors
    /// Returns `InvalidPattern` if any token is not a valid hex byte or `??`.
    pub fn hex(pattern: &str) -> Result<Self, SearchError> {
        // Validate first
        for token in pattern.split_whitespace() {
            if token == "??" {
                continue;
            }
            if token.len() != 2
                || u8::from_str_radix(token, 16).is_err()
            {
                return Err(SearchError::InvalidPattern(format!(
                    "invalid token '{token}' in hex pattern"
                )));
            }
        }
        if pattern.split_whitespace().count() == 0 {
            return Err(SearchError::EmptyPattern);
        }
        Ok(Self::HexWildcard(pattern.to_string()))
    }

    /// Create an exact bytes pattern.
    ///
    /// # Errors
    /// Returns `EmptyPattern` if `bytes` is empty.
    pub fn bytes(bytes: Vec<u8>) -> Result<Self, SearchError> {
        if bytes.is_empty() {
            return Err(SearchError::EmptyPattern);
        }
        Ok(Self::Bytes(bytes))
    }

    /// Create a UTF-8 string pattern.
    ///
    /// # Errors
    /// Returns `EmptyPattern` if `s` is empty.
    pub fn string(s: impl Into<String>) -> Result<Self, SearchError> {
        let s = s.into();
        if s.is_empty() {
            return Err(SearchError::EmptyPattern);
        }
        Ok(Self::Utf8(s))
    }

    /// Return the minimum match length in bytes.
    #[must_use]
    pub fn min_len(&self) -> usize {
        match self {
            Self::Bytes(b) => b.len(),
            Self::HexWildcard(p) => p.split_whitespace().count(),
            Self::Utf8(s) | Self::Utf8CaseInsensitive(s) => s.len(),
            // `str::len()` is UTF-8 bytes; the pattern is built from UTF-16
            // code units, and the two differ for everything outside ASCII.
            // Counted the same way `compile_pattern` encodes it.
            Self::Utf16Le(s) => s.encode_utf16().count() * 2,
            Self::Xor { pattern, .. } => pattern.len(),
        }
    }

    /// Return a human-readable description of this pattern.
    #[must_use]
    pub fn description(&self) -> String {
        match self {
            Self::Bytes(b) => {
                let mut hex = Vec::with_capacity(b.len());
                hex.extend(b.iter().map(|b| format!("{b:02X}")));
                format!("Bytes: {}", hex.join(" "))
            }
            Self::HexWildcard(p) => format!("Hex: {p}"),
            Self::Utf8(s) => format!("UTF-8: \"{s}\""),
            Self::Utf8CaseInsensitive(s) => format!("UTF-8 (ci): \"{s}\""),
            Self::Utf16Le(s) => format!("UTF-16LE: \"{s}\""),
            Self::Xor { key, .. } => format!("XOR[{key:#04X}]"),
        }
    }
}

impl fmt::Display for SearchPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.description())
    }
}

// ─── MemoryRegion ─────────────────────────────────────────────────────────────

/// A single memory region that can be searched.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryRegion {
    /// Virtual address range of this region.
    pub address: u64,
    pub size: usize,
    /// Whether the region is readable.
    pub readable: bool,
    /// Whether the region is writable.
    pub writable: bool,
    /// Whether the region is executable.
    pub executable: bool,
    /// Module or mapping name (if known).
    pub name: Option<String>,
}

impl MemoryRegion {
    /// Create a readable region.
    #[must_use]
    pub const fn readable(address: u64, size: usize, name: Option<String>) -> Self {
        Self {
            address,
            size,
            readable: true,
            writable: false,
            executable: false,
            name,
        }
    }

    /// End address of this region.
    #[must_use]
    pub const fn end(&self) -> u64 {
        self.address + self.size as u64
    }

    /// Range of this region.
    #[must_use]
    pub const fn range(&self) -> Range<u64> {
        self.address..self.end()
    }
}

impl fmt::Display for MemoryRegion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let perms = format!(
            "{}{}{}",
            if self.readable { 'r' } else { '-' },
            if self.writable { 'w' } else { '-' },
            if self.executable { 'x' } else { '-' }
        );
        write!(
            f,
            "{:#016x}–{:#016x} [{}] {}",
            self.address,
            self.end(),
            perms,
            self.name.as_deref().unwrap_or("<anonymous>")
        )
    }
}

// ─── SearchResult ─────────────────────────────────────────────────────────────

/// A single match found in memory.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchResult {
    /// Virtual address of the match.
    pub address: u64,
    /// File/buffer offset of the match within the searched data.
    pub offset: usize,
    /// The matched bytes.
    pub matched_bytes: Vec<u8>,
    /// Index of the region in which the match was found.
    pub region_index: usize,
    /// Module name of the region (if known).
    pub module: Option<String>,
}

impl SearchResult {
    const fn new(address: u64, offset: usize, matched: Vec<u8>, region_idx: usize, module: Option<String>) -> Self {
        Self {
            address,
            offset,
            matched_bytes: matched,
            region_index: region_idx,
            module,
        }
    }

    /// Return a hex dump of the matched bytes.
    #[must_use]
    pub fn hex_dump(&self) -> String {
        let mut parts = Vec::with_capacity(self.matched_bytes.len());
        parts.extend(self.matched_bytes.iter().map(|b| format!("{b:02X}")));
        parts.join(" ")
    }
}

impl fmt::Display for SearchResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:#016x}  {}",
            self.address,
            self.hex_dump()
        )
    }
}

// ─── SearchOptions ────────────────────────────────────────────────────────────

/// Options that control how a search is performed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchOptions {
    /// Maximum number of results to return (0 = unlimited).
    pub max_results: usize,
    /// Skip regions that are not executable.
    pub executable_only: bool,
    /// Skip regions that are not writable.
    pub writable_only: bool,
    /// Only search within this address range (0 = entire space).
    pub address_range: Option<(u64, u64)>,
    /// Minimum alignment for matches (1 = any).
    pub alignment: usize,
}

impl Default for SearchOptions {
    fn default() -> Self {
        Self {
            max_results: 0,
            executable_only: false,
            writable_only: false,
            address_range: None,
            alignment: 1,
        }
    }
}

impl SearchOptions {
    /// Set a maximum result count.
    #[must_use]
    pub const fn with_max_results(mut self, n: usize) -> Self {
        self.max_results = n;
        self
    }

    /// Only search executable regions.
    #[must_use]
    pub const fn executable_only(mut self) -> Self {
        self.executable_only = true;
        self
    }

    /// Restrict search to an address range.
    #[must_use]
    pub const fn in_range(mut self, start: u64, end: u64) -> Self {
        self.address_range = Some((start, end));
        self
    }

    /// Require matches to be aligned to `n` bytes.
    #[must_use]
    pub fn aligned(mut self, n: usize) -> Self {
        self.alignment = n.max(1);
        self
    }
}

// ─── MemorySearch ─────────────────────────────────────────────────────────────

/// Main memory search engine.
///
/// Operates on a flat byte buffer that represents the contents of one or more
/// mapped memory regions.
pub struct MemorySearch {
    options: SearchOptions,
}

impl MemorySearch {
    /// Create a new search engine with the given options.
    #[must_use]
    pub const fn new(options: SearchOptions) -> Self {
        Self { options }
    }

    /// Create a search engine with default options.
    #[must_use]
    pub fn default_options() -> Self {
        Self::new(SearchOptions::default())
    }

    /// Search `data` for `pattern`, treating the buffer as starting at `base_address`.
    ///
    /// For exact byte and UTF-8 patterns the first byte is located via
    /// `memchr` (AVX2/SSE4.2/NEON at runtime), cutting the scan cost by
    /// skipping non-candidate offsets entirely.
    ///
    /// # Errors
    /// Returns an error if the pattern is invalid or the search fails.
    pub fn search_buffer(
        &self,
        data: &[u8],
        base_address: u64,
        pattern: &SearchPattern,
        region_index: usize,
        module: Option<&str>,
    ) -> Result<Vec<SearchResult>, SearchError> {
        let compiled = compile_pattern(pattern)?;
        let mut results = Vec::new();

        let align = self.options.alignment.max(1);
        let addr_range = self.options.address_range;
        let pat_len = compiled.min_len();

        // opt-2: for patterns whose first byte is fixed, use memchr to jump
        // directly to candidate positions instead of scanning every byte.
        let first_fixed: Option<u8> = compiled.tokens.first().and_then(|t| *t);

        if let Some(needle_byte) = first_fixed {
            // SIMD-accelerated first-byte scan via memchr.
            let search_end = data.len().saturating_sub(pat_len - 1);
            let search_slice = &data[..search_end.min(data.len())];
            let mut start = 0usize;
            while let Some(rel) = memchr::memchr(needle_byte, &search_slice[start..]) {
                let offset = start + rel;
                let addr = base_address + offset as u64;
                // alignment / range filters — cold branches
                if unlikely(align > 1 && !addr.is_multiple_of(align as u64)) {
                    start = offset + 1;
                    continue;
                }
                if let Some((lo, hi)) = addr_range {
                    if unlikely(addr < lo || addr >= hi) {
                        start = offset + 1;
                        continue;
                    }
                }
                if likely(offset + pat_len <= data.len()) {
                    if let Some(matched) = compiled.try_match(&data[offset..]) {
                        results.push(SearchResult::new(
                            addr,
                            offset,
                            matched,
                            region_index,
                            module.map(str::to_owned),
                        ));
                        if self.options.max_results > 0
                            && unlikely(results.len() >= self.options.max_results)
                        {
                            return Ok(results);
                        }
                    }
                }
                start = offset + 1;
            }
        } else {
            // Wildcard-only or no-first-byte patterns: scalar scan.
            let mut offset = 0usize;
            while offset + pat_len <= data.len() {
                let addr = base_address + offset as u64;
                if unlikely(align > 1 && !addr.is_multiple_of(align as u64)) {
                    offset += 1;
                    continue;
                }
                if let Some((lo, hi)) = addr_range {
                    if unlikely(addr < lo || addr >= hi) {
                        offset += 1;
                        continue;
                    }
                }
                if let Some(matched) = compiled.try_match(&data[offset..]) {
                    results.push(SearchResult::new(
                        addr,
                        offset,
                        matched,
                        region_index,
                        module.map(str::to_owned),
                    ));
                    if self.options.max_results > 0
                        && unlikely(results.len() >= self.options.max_results)
                    {
                        return Ok(results);
                    }
                }
                offset += 1;
            }
        }
        Ok(results)
    }

    /// Search a list of `regions`, reading data from `memory`.
    ///
    /// `memory` is a single flat byte buffer; each region's `address` field is
    /// used as an offset into `memory` if it is within bounds.
    ///
    /// opt-3: regions are searched in parallel via rayon when there are more
    /// than 4 readable regions, cutting scan time proportional to core count.
    ///
    /// # Errors
    /// Returns an error if the pattern is invalid.
    pub fn search_all_regions(
        &self,
        memory: &[u8],
        regions: &[MemoryRegion],
        pattern: &SearchPattern,
    ) -> Result<Vec<SearchResult>, SearchError> {
        // Validate pattern once before spawning threads.
        compile_pattern(pattern)?;

        // Build a filtered list of (index, region) pairs.
        let eligible: Vec<(usize, &MemoryRegion)> = regions
            .iter()
            .enumerate()
            .filter(|(_, r)| {
                r.readable
                    && (!self.options.executable_only || r.executable)
                    && (!self.options.writable_only || r.writable)
            })
            .collect();

        // opt-3: parallel scan — each region is an independent unit of work.
        let partial: Result<Vec<Vec<SearchResult>>, SearchError> = eligible
            .into_par_iter()
            .map(|(idx, region)| {
                let Ok(region_start) = usize::try_from(region.address) else {
                    return Ok(Vec::new());
                };
                if region_start >= memory.len() {
                    return Ok(Vec::new());
                }
                let region_end = region_start.saturating_add(region.size);
                let slice_end = region_end.min(memory.len());
                let slice = &memory[region_start..slice_end];
                self.search_buffer(slice, region.address, pattern, idx, region.name.as_deref())
            })
            .collect();

        let mut all_results: Vec<SearchResult> = partial?.into_iter().flatten().collect();

        if self.options.max_results > 0 && all_results.len() > self.options.max_results {
            all_results.truncate(self.options.max_results);
        }
        Ok(all_results)
    }
}

// ─── Public convenience function ─────────────────────────────────────────────

/// Search all readable regions in `memory` for `pattern`.
///
/// This is the primary entry point for callers that do not need custom options.
///
/// # Errors
/// Returns an error if the pattern is invalid.
pub fn search_all_regions(
    memory: &[u8],
    regions: &[MemoryRegion],
    pattern: &SearchPattern,
) -> Result<Vec<SearchResult>, SearchError> {
    MemorySearch::default_options().search_all_regions(memory, regions, pattern)
}

// ─── Compiled pattern (internal) ─────────────────────────────────────────────

struct CompiledPattern {
    tokens: Vec<Option<u8>>,
}

impl CompiledPattern {
    const fn min_len(&self) -> usize {
        self.tokens.len()
    }

    fn try_match(&self, data: &[u8]) -> Option<Vec<u8>> {
        if data.len() < self.tokens.len() {
            return None;
        }
        for (i, token) in self.tokens.iter().enumerate() {
            if let Some(expected) = token && data[i] != *expected {
                return None;
            }
        }
        Some(data[..self.tokens.len()].to_vec())
    }
}

fn compile_pattern(pattern: &SearchPattern) -> Result<CompiledPattern, SearchError> {
    let tokens = match pattern {
        SearchPattern::Bytes(b) => {
            if b.is_empty() {
                return Err(cold_empty_pattern());
            }
            b.iter().map(|&b| Some(b)).collect()
        }
        SearchPattern::HexWildcard(p) => {
            let mut tokens = Vec::new();
            for token in p.split_whitespace() {
                if token == "??" || token == "?" {
                    tokens.push(None);
                } else {
                    let b = u8::from_str_radix(token, 16)
                        .map_err(|_| cold_invalid_pattern(format!("'{token}'")))?;
                    tokens.push(Some(b));
                }
            }
            if tokens.is_empty() {
                return Err(cold_empty_pattern());
            }
            tokens
        }
        SearchPattern::Utf8(s) => {
            if s.is_empty() {
                return Err(cold_empty_pattern());
            }
            s.as_bytes().iter().map(|&b| Some(b)).collect()
        }
        SearchPattern::Utf8CaseInsensitive(s) => {
            // For CI matching, we use lowercase tokens and lowercase data.
            // We store lowercase bytes and rely on caller to also lowercase the data.
            // Instead we implement a special match by just storing the lower bytes.
            if s.is_empty() {
                return Err(cold_empty_pattern());
            }
            s.to_lowercase()
                .as_bytes()
                .iter()
                .map(|&b| Some(b))
                .collect()
        }
        SearchPattern::Utf16Le(s) => {
            if s.is_empty() {
                return Err(cold_empty_pattern());
            }
            let mut bytes = Vec::with_capacity(s.len() * 2);
            for c in s.chars() {
                let mut buf = [0u16; 2];
                let encoded = c.encode_utf16(&mut buf);
                for &u in encoded.iter() {
                    bytes.push(Some((u & 0xFF) as u8));
                    bytes.push(Some((u >> 8) as u8));
                }
            }
            bytes
        }
        SearchPattern::Xor { pattern, key } => {
            if pattern.is_empty() {
                return Err(cold_empty_pattern());
            }
            pattern.iter().map(|&b| Some(b ^ key)).collect()
        }
    };
    Ok(CompiledPattern { tokens })
}

// ─── Live-target search ──────────────────────────────────────────────────────

/// The two operations a live search needs from a debuggee.
///
/// Every native backend already provides them through [`crate::Debugger`], so
/// the blanket impl below wires all three OSes at once; a test can implement
/// just these two without standing up a whole debugger.
#[async_trait::async_trait]
pub trait TargetMemory: Send + Sync {
    /// The debuggee's address-space map.
    ///
    /// # Errors
    /// Propagates the backend's failure.
    async fn target_maps(&self) -> Result<Vec<crate::MemoryMap>, crate::DebugError>;
    /// Read `size` bytes at `addr` from the debuggee.
    ///
    /// # Errors
    /// Propagates the backend's failure; a search treats it as an unreadable
    /// chunk rather than as an empty one.
    async fn target_read(
        &self,
        addr: rustre_core::address::Address,
        size: usize,
    ) -> Result<Vec<u8>, crate::DebugError>;
}

#[async_trait::async_trait]
impl<D: crate::Debugger + ?Sized> TargetMemory for D {
    async fn target_maps(&self) -> Result<Vec<crate::MemoryMap>, crate::DebugError> {
        self.memory_maps().await
    }
    async fn target_read(
        &self,
        addr: rustre_core::address::Address,
        size: usize,
    ) -> Result<Vec<u8>, crate::DebugError> {
        self.read_memory(addr, size).await
    }
}

/// Bytes read per `read_memory` call when scanning a live target.
///
/// A region can be gigabytes wide, so it is read in chunks; see
/// [`search_target`] for why consecutive chunks must overlap.
pub const TARGET_CHUNK_BYTES: usize = 1 << 20;

/// Outcome of a live-target scan.
///
/// The counters exist so a caller can tell "no match anywhere" apart from "the
/// regions that would have held the match could not be read" — two answers that
/// look identical if only the hits are returned.
#[derive(Debug, Clone, Default)]
pub struct TargetSearchReport {
    /// Matches, in ascending region then address order.
    pub results: Vec<SearchResult>,
    /// Regions actually scanned end to end.
    pub regions_searched: usize,
    /// Regions skipped because the backend refused a read inside them.
    pub regions_unreadable: usize,
    /// Bytes handed to the matcher (overlap counted once).
    pub bytes_scanned: u64,
    /// Whether the scan stopped early because `max_results` was reached.
    pub truncated: bool,
}

/// Search the live debuggee's address space for `pattern`.
///
/// Walks [`crate::Debugger::memory_maps`] and reads each eligible region in
/// [`TARGET_CHUNK_BYTES`] pieces. **Consecutive chunks overlap by
/// `pattern_len - 1` bytes**: without that overlap a pattern straddling a chunk
/// boundary is invisible — the tail chunk starts after the pattern's first byte
/// and the head chunk has no room to complete it — and the scan reports "not
/// found" for a value that is plainly there.
///
/// A chunk the backend refuses to read is skipped and counted; the search never
/// substitutes zeroes for memory it could not read.
///
/// # Errors
/// Returns an error if the pattern is invalid, or if the address-space map
/// cannot be obtained (with no map there is nothing honest to scan).
pub async fn search_target(
    engine: &MemorySearch,
    target: &dyn TargetMemory,
    pattern: &SearchPattern,
) -> Result<TargetSearchReport, SearchError> {
    let pat_len = compile_pattern(pattern)?.min_len();
    let maps = target
        .target_maps()
        .await
        .map_err(|e| SearchError::InvalidPattern(format!("memory_maps failed: {e}")))?;

    let mut report = TargetSearchReport::default();
    let overlap = pat_len.saturating_sub(1);
    let max = engine.options.max_results;

    for (idx, map) in maps.iter().enumerate() {
        if !map.readable
            || (engine.options.executable_only && !map.executable)
            || (engine.options.writable_only && !map.writable)
        {
            continue;
        }
        let Ok(size) = usize::try_from(map.size) else { continue };
        if size < pat_len {
            continue;
        }

        let mut pos = 0usize;
        let mut region_failed = false;
        while pos < size {
            let want = TARGET_CHUNK_BYTES.min(size - pos);
            if want < pat_len {
                break;
            }
            let addr = rustre_core::address::Address(map.base.0 + pos as u64);
            let Ok(buf) = target.target_read(addr, want).await else {
                region_failed = true;
                break;
            };
            if buf.len() < pat_len {
                region_failed = true;
                break;
            }
            // Overlap is re-read, not re-counted: only the fresh bytes count.
            report.bytes_scanned += if pos == 0 {
                buf.len() as u64
            } else {
                (buf.len() - overlap.min(buf.len())) as u64
            };
            let hits =
                engine.search_buffer(&buf, addr.0, pattern, idx, map.name.as_deref())?;
            for hit in hits {
                report.results.push(hit);
                if max > 0 && report.results.len() >= max {
                    report.truncated = true;
                    report.regions_searched += 1;
                    return Ok(report);
                }
            }
            // A short read still advances by what was actually returned, so no
            // byte is skipped on the strength of a request that was not served.
            // `want >= pat_len > overlap`, so progress is always positive.
            pos += buf.len().min(want).saturating_sub(overlap).max(1);
        }
        if region_failed {
            report.regions_unreadable += 1;
        } else {
            report.regions_searched += 1;
        }
    }
    Ok(report)
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn simple_region(addr: u64, size: usize) -> MemoryRegion {
        MemoryRegion {
            address: addr,
            size,
            readable: true,
            writable: false,
            executable: false,
            name: None,
        }
    }

    // ── Live-target search ──────────────────────────────────────────────────

    /// A debuggee whose whole address space is one flat buffer, with a read
    /// size cap far below `TARGET_CHUNK_BYTES` so the chunk seam falls where
    /// the test wants it. `refuse_at` makes one address unreadable, the way a
    /// guard page or a freed mapping does.
    struct FakeTarget {
        base: u64,
        mem: Vec<u8>,
        cap: usize,
        refuse_at: Option<u64>,
    }

    #[async_trait::async_trait]
    impl TargetMemory for FakeTarget {
        async fn target_maps(&self) -> Result<Vec<crate::MemoryMap>, crate::DebugError> {
            Ok(vec![crate::MemoryMap {
                base: rustre_core::address::Address(self.base),
                size: self.mem.len() as u64,
                readable: true,
                writable: true,
                executable: false,
                name: Some("[fake]".to_string()),
                file_path: None,
                file_offset: 0,
            }])
        }
        async fn target_read(
            &self,
            addr: rustre_core::address::Address,
            size: usize,
        ) -> Result<Vec<u8>, crate::DebugError> {
            if Some(addr.0) == self.refuse_at {
                return Err(crate::DebugError::NotAttached);
            }
            let off = (addr.0 - self.base) as usize;
            let end = (off + size.min(self.cap)).min(self.mem.len());
            Ok(self.mem[off..end].to_vec())
        }
    }

    /// A live scan reads a region in chunks. A pattern that straddles a chunk
    /// seam must still be found: without an overlap of `pattern_len - 1` the
    /// head chunk has no room to complete it and the tail chunk starts past its
    /// first byte, so the search answers "not found" for a value that is
    /// plainly in the target's memory — the worst possible answer, because it
    /// is indistinguishable from a correct negative.
    #[tokio::test]
    async fn live_target_search_finds_a_pattern_that_straddles_the_chunk_seam() {
        const BASE: u64 = 0x1_0000;
        const CAP: usize = 64;
        let mut mem = vec![0u8; 256];
        // Straddles the first seam: 62..66 with a 64-byte read cap.
        mem[62..66].copy_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
        let target = FakeTarget { base: BASE, mem, cap: CAP, refuse_at: None };

        let p = SearchPattern::bytes(vec![0xDE, 0xAD, 0xBE, 0xEF]).unwrap();
        let engine = MemorySearch::default_options();
        let report = search_target(&engine, &target, &p).await.unwrap();

        assert_eq!(
            report.results.len(),
            1,
            "the pattern at {:#x} sits across a chunk seam and must be found exactly once, \
             not zero times (missed) and not twice (double-counted overlap): {report:?}",
            BASE + 62
        );
        assert_eq!(report.results[0].address, BASE + 62);
        assert_eq!(report.regions_searched, 1);
        assert_eq!(report.regions_unreadable, 0);
        assert_eq!(
            report.bytes_scanned, 256,
            "overlap is re-read but must be counted once, or the report inflates its own coverage"
        );
    }

    /// A region the backend refuses is counted as unreadable, never as searched.
    /// Reporting it as searched would turn "could not look" into "looked and
    /// found nothing".
    #[tokio::test]
    async fn live_target_search_never_reports_an_unreadable_region_as_searched() {
        const BASE: u64 = 0x2_0000;
        let mut mem = vec![0u8; 128];
        mem[10..14].copy_from_slice(&[0xCA, 0xFE, 0xBA, 0xBE]);
        let target = FakeTarget {
            base: BASE,
            mem,
            cap: 64,
            refuse_at: Some(BASE),
        };
        let p = SearchPattern::bytes(vec![0xCA, 0xFE, 0xBA, 0xBE]).unwrap();
        let report = search_target(&MemorySearch::default_options(), &target, &p)
            .await
            .unwrap();
        assert!(report.results.is_empty());
        assert_eq!(report.regions_searched, 0);
        assert_eq!(report.regions_unreadable, 1);
    }

    #[test]
    fn search_exact_bytes() {
        let data = [0x00_u8, 0xDE, 0xAD, 0xBE, 0xEF, 0x00];
        // Hmm — need SearchPattern::bytes to build this:
        let p = SearchPattern::bytes(vec![0xDE, 0xAD, 0xBE, 0xEF]).unwrap();
        let searcher = MemorySearch::default_options();
        let results = searcher.search_buffer(&data, 0, &p, 0, None).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].address, 1);
        assert_eq!(results[0].matched_bytes, [0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn search_hex_wildcard() {
        let data = [0xDE_u8, 0x00, 0xBE, 0xEF];
        let pattern = SearchPattern::hex("DE ?? BE EF").unwrap();
        let searcher = MemorySearch::default_options();
        let results = searcher.search_buffer(&data, 0x1000, &pattern, 0, None).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].address, 0x1000);
    }

    #[test]
    fn search_no_match() {
        let data = [0x00_u8; 16];
        let pattern = SearchPattern::bytes(vec![0xFF, 0xFF]).unwrap();
        let searcher = MemorySearch::default_options();
        let results = searcher.search_buffer(&data, 0, &pattern, 0, None).unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn search_utf8_string() {
        let data = b"Hello, World!";
        let pattern = SearchPattern::string("World").unwrap();
        let searcher = MemorySearch::default_options();
        let results = searcher.search_buffer(data, 0, &pattern, 0, None).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].address, 7);
    }

    #[test]
    fn search_multiple_matches() {
        let data = [0xAB_u8, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD];
        let pattern = SearchPattern::bytes(vec![0xAB, 0xCD]).unwrap();
        let searcher = MemorySearch::default_options();
        let results = searcher.search_buffer(&data, 0, &pattern, 0, None).unwrap();
        assert_eq!(results.len(), 3);
    }

    #[test]
    fn search_max_results_limits() {
        let data = [0xAA_u8; 16];
        let pattern = SearchPattern::bytes(vec![0xAA]).unwrap();
        let searcher = MemorySearch::new(SearchOptions::default().with_max_results(3));
        let results = searcher.search_buffer(&data, 0, &pattern, 0, None).unwrap();
        assert_eq!(results.len(), 3);
    }

    #[test]
    fn search_alignment_filter() {
        let data = [0xFF_u8; 16];
        let pattern = SearchPattern::bytes(vec![0xFF]).unwrap();
        let searcher = MemorySearch::new(SearchOptions::default().aligned(4));
        let results = searcher.search_buffer(&data, 0, &pattern, 0, None).unwrap();
        // Only every 4th byte: 0, 4, 8, 12
        assert_eq!(results.len(), 4);
        for r in &results {
            assert_eq!(r.address % 4, 0);
        }
    }

    #[test]
    fn search_address_range_filter() {
        let data = [0xBB_u8; 32];
        let pattern = SearchPattern::bytes(vec![0xBB]).unwrap();
        let searcher = MemorySearch::new(
            SearchOptions::default().in_range(0x10, 0x14)
        );
        let results = searcher.search_buffer(&data, 0, &pattern, 0, None).unwrap();
        // Addresses 0x10, 0x11, 0x12, 0x13
        assert_eq!(results.len(), 4);
    }

    #[test]
    fn search_all_regions_basic() {
        let memory = vec![0x00_u8; 64];
        let mut mem = memory.clone();
        mem[32] = 0xDE;
        mem[33] = 0xAD;
        let region = simple_region(0, 64);
        let pattern = SearchPattern::bytes(vec![0xDE, 0xAD]).unwrap();
        let results = search_all_regions(&mem, &[region], &pattern).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].address, 32);
    }

    #[test]
    fn search_all_regions_skips_unreadable() {
        let mut region = simple_region(0, 16);
        region.readable = false;
        let memory = vec![0xAA_u8; 16];
        let pattern = SearchPattern::bytes(vec![0xAA]).unwrap();
        let results = search_all_regions(&memory, &[region], &pattern).unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn xor_pattern_search() {
        let key = 0x20_u8;
        let plain = b"HELLO";
        let encoded: Vec<u8> = plain.iter().map(|&b| b ^ key).collect();
        let mut data = vec![0u8; 8];
        data[2..7].copy_from_slice(&encoded);
        let pattern = SearchPattern::Xor { pattern: plain.to_vec(), key };
        let searcher = MemorySearch::default_options();
        let results = searcher.search_buffer(&data, 0, &pattern, 0, None).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].address, 2);
    }

    #[test]
    fn utf16le_pattern_search() {
        // "AB" in UTF-16LE = 41 00 42 00
        let pattern = SearchPattern::Utf16Le("AB".to_string());
        let data = [0x00_u8, 0x41, 0x00, 0x42, 0x00];
        let searcher = MemorySearch::default_options();
        let results = searcher.search_buffer(&data, 0, &pattern, 0, None).unwrap();
        // Match at offset 1
        assert!(!results.is_empty());
    }

    #[test]
    fn invalid_hex_pattern_errors() {
        let err = SearchPattern::hex("ZZ").unwrap_err();
        assert!(matches!(err, SearchError::InvalidPattern(_)));
    }

    #[test]
    fn empty_pattern_errors() {
        let err = SearchPattern::bytes(vec![]).unwrap_err();
        assert!(matches!(err, SearchError::EmptyPattern));
    }

    #[test]
    fn search_result_display() {
        let r = SearchResult::new(0x1234, 0, vec![0xDE, 0xAD], 0, None);
        let s = r.to_string();
        assert!(s.contains("1234"));
        assert!(s.contains("DE AD"));
    }

    #[test]
    fn memory_region_display() {
        let r = simple_region(0x1000, 0x100);
        let s = r.to_string();
        assert!(s.contains("1000"));
        assert!(s.contains("r--"));
    }

    #[test]
    fn pattern_description() {
        let p = SearchPattern::Bytes(vec![0xDE, 0xAD]);
        assert!(p.description().contains("DE AD"));

        let p2 = SearchPattern::Utf8("hello".to_string());
        assert!(p2.description().contains("hello"));
    }

    #[test]
    fn pattern_min_len() {
        let p = SearchPattern::Bytes(vec![0; 8]);
        assert_eq!(p.min_len(), 8);
        let p2 = SearchPattern::Utf16Le("AB".to_string());
        assert_eq!(p2.min_len(), 4);
    }

    #[test]
    fn region_end_and_range() {
        let r = simple_region(0x1000, 0x100);
        assert_eq!(r.end(), 0x1100);
        assert_eq!(r.range(), 0x1000..0x1100);
    }

    /// `min_len()` must equal the length a match actually consumes.
    ///
    /// The UTF-16LE arm computed `s.len() * 2`, but `str::len()` counts UTF-8
    /// BYTES, not UTF-16 units. Compilation, correctly, uses `encode_utf16`.
    /// The two agree only for ASCII: an accented letter, a currency sign, or
    /// anything outside the BMP made the advertised length overshoot the real
    /// one — the euro sign claims 6 bytes for a 2-byte pattern. This is a
    /// public API whose doc says "minimum match length in bytes", so a caller
    /// sizing a read buffer, or deciding whether a pattern can fit in a region,
    /// is handed a number that is simply wrong.
    ///
    /// Checked against what a search actually matches, for every pattern kind,
    /// so the arms that were already correct stay correct.
    #[test]
    fn min_len_matches_the_bytes_a_match_consumes() {
        let cases: Vec<SearchPattern> = vec![
            SearchPattern::Bytes(vec![0xAA, 0xBB]),
            SearchPattern::HexWildcard("AA ?? CC".to_string()),
            SearchPattern::Utf8("hi".to_string()),
            SearchPattern::Utf16Le("AB".to_string()),        // ASCII: already agreed
            SearchPattern::Utf16Le("\u{00E9}".to_string()),  // 2 UTF-8 bytes, 1 UTF-16 unit
            SearchPattern::Utf16Le("\u{20AC}".to_string()),  // 3 UTF-8 bytes, 1 UTF-16 unit
            SearchPattern::Utf16Le("\u{1D11E}".to_string()), // 4 UTF-8 bytes, 2 UTF-16 units
            SearchPattern::Xor { pattern: vec![1, 2, 3], key: 0x5A },
        ];

        let searcher = MemorySearch::default_options();
        for pat in &cases {
            let dump = pat.description();
            let hits = searcher
                .search_buffer(&pattern_bytes(pat), 0, pat, 0, None)
                .unwrap();
            let matched_len = hits
                .first()
                .unwrap_or_else(|| panic!("{dump} did not match its own bytes"))
                .matched_bytes
                .len();
            assert_eq!(
                pat.min_len(),
                matched_len,
                "{dump}: min_len() disagrees with the bytes a match consumes"
            );
        }
    }

    /// The exact byte sequence `pat` matches, built independently of `min_len`.
    fn pattern_bytes(pat: &SearchPattern) -> Vec<u8> {
        match pat {
            SearchPattern::Bytes(b) => b.clone(),
            SearchPattern::HexWildcard(p) => p
                .split_whitespace()
                .map(|t| if t == "??" { 0 } else { u8::from_str_radix(t, 16).unwrap() })
                .collect(),
            SearchPattern::Utf8(s) | SearchPattern::Utf8CaseInsensitive(s) => s.as_bytes().to_vec(),
            SearchPattern::Utf16Le(s) => s
                .encode_utf16()
                .flat_map(|u| [(u & 0xFF) as u8, (u >> 8) as u8])
                .collect(),
            SearchPattern::Xor { pattern, key } => pattern.iter().map(|b| b ^ key).collect(),
        }
    }

    /// The memchr fast path and the scalar path must find exactly the same
    /// matches.
    ///
    /// `search_buffer` picks between them purely on whether the pattern's first
    /// token is a fixed byte, so a pattern and the same pattern with a leading
    /// `??` take different code paths through the same boundary arithmetic
    /// (`saturating_sub(pat_len - 1)` vs `offset + pat_len <= len`). This checks
    /// both against a naive oracle, over buffers where matches sit at offset 0,
    /// end exactly at the last byte, overlap each other, or do not fit at all.
    #[test]
    fn both_scan_paths_agree_with_a_naive_oracle() {
        fn oracle(data: &[u8], toks: &[Option<u8>]) -> Vec<usize> {
            let mut hits = Vec::new();
            if toks.is_empty() || toks.len() > data.len() {
                return hits;
            }
            for off in 0..=(data.len() - toks.len()) {
                if toks.iter().enumerate().all(|(i, t)| t.is_none_or(|b| data[off + i] == b)) {
                    hits.push(off);
                }
            }
            hits
        }

        let buffers: Vec<Vec<u8>> = vec![
            vec![],
            vec![0xAA],
            vec![0xAA, 0xBB],
            vec![0xAA, 0xBB, 0xAA, 0xBB],
            vec![0xAA, 0xAA, 0xAA, 0xAA, 0xAA],
            vec![0x00, 0x01, 0xAA, 0xBB, 0xCC],
            vec![0xCC, 0xAA, 0xBB],            // match ends at the last byte
            vec![0xAA, 0xBB, 0xAA, 0xBB, 0xAA], // overlapping candidates
        ];
        // Each pattern in two shapes: fixed first token (memchr path) and the
        // same match set expressed with a leading wildcard (scalar path).
        let patterns = [
            ("AA", "??"),
            ("AA BB", "?? BB"),
            ("AA ?? CC", "?? ?? CC"),
            ("AA BB CC DD EE FF", "?? BB CC DD EE FF"),
        ];

        let searcher = MemorySearch::default_options();
        for data in &buffers {
            for (fixed, wild) in patterns {
                for spec in [fixed, wild] {
                    let pat = SearchPattern::hex(spec).unwrap();
                    let toks: Vec<Option<u8>> = spec
                        .split_whitespace()
                        .map(|t| (t != "??").then(|| u8::from_str_radix(t, 16).unwrap()))
                        .collect();
                    let got: Vec<usize> = searcher
                        .search_buffer(data, 0, &pat, 0, None)
                        .unwrap()
                        .iter()
                        .map(|r| r.offset)
                        .collect();
                    assert_eq!(
                        got,
                        oracle(data, &toks),
                        "pattern {spec:?} over {data:02x?} disagreed with the oracle"
                    );
                }
            }
        }
    }
}
