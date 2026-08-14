//! Memory analysis: region classification, entropy scanning, string scanning,
//! pointer scanning, pattern scanning, and final report generation.

pub use std::collections::HashMap;
use std::fmt;

// ─────────────────────────────────────────────────────────────────────────────
// Re-use types from crate root where available; otherwise define lightweight
// stand-alone versions so this module compiles independently.
// ─────────────────────────────────────────────────────────────────────────────

/// A virtual address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Va(pub u64);

impl Va {
    #[must_use] 
    pub const fn new(v: u64) -> Self {
        Self(v)
    }
    #[must_use] 
    pub const fn as_u64(self) -> u64 {
        self.0
    }
    pub fn checked_add(self, n: u64) -> Option<Self> {
        self.0.checked_add(n).map(Va)
    }
    #[must_use] 
    pub const fn wrapping_add(self, n: u64) -> Self {
        Self(self.0.wrapping_add(n))
    }
    #[must_use] 
    pub const fn offset_from(self, base: Self) -> Option<u64> {
        if self.0 >= base.0 {
            Some(self.0 - base.0)
        } else {
            None
        }
    }
}

impl fmt::Display for Va {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#018x}", self.0)
    }
}

/// A half-open address range `[start, end)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VaRange {
    pub start: Va,
    pub end: Va,
}

impl VaRange {
    #[must_use] 
    pub const fn new(start: Va, end: Va) -> Self {
        Self { start, end }
    }
    #[must_use] 
    pub const fn len(&self) -> u64 {
        self.end.0.saturating_sub(self.start.0)
    }
    #[must_use] 
    pub const fn is_empty(&self) -> bool {
        self.len() == 0
    }
    #[must_use] 
    pub const fn contains(&self, va: Va) -> bool {
        va.0 >= self.start.0 && va.0 < self.end.0
    }
    #[must_use] 
    pub const fn overlaps(&self, other: &Self) -> bool {
        self.start.0 < other.end.0 && other.start.0 < self.end.0
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// RegionKind
// ─────────────────────────────────────────────────────────────────────────────

/// Classification of a memory region.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RegionKind {
    Code,
    Data,
    Stack,
    Heap,
    Mapped,
    ReadOnly,
    Unknown,
}

impl fmt::Display for RegionKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Code => "code",
            Self::Data => "data",
            Self::Stack => "stack",
            Self::Heap => "heap",
            Self::Mapped => "mapped",
            Self::ReadOnly => "rodata",
            Self::Unknown => "unknown",
        };
        write!(f, "{s}")
    }
}

/// Permission flags for a memory region.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegionPerms {
    pub read: bool,
    pub write: bool,
    pub execute: bool,
}

impl RegionPerms {
    #[must_use] 
    pub const fn new(read: bool, write: bool, execute: bool) -> Self {
        Self {
            read,
            write,
            execute,
        }
    }

    #[must_use] 
    pub const fn rx() -> Self {
        Self::new(true, false, true)
    }
    #[must_use] 
    pub const fn rw() -> Self {
        Self::new(true, true, false)
    }
    #[must_use] 
    pub const fn ro() -> Self {
        Self::new(true, false, false)
    }
    #[must_use] 
    pub const fn rwx() -> Self {
        Self::new(true, true, true)
    }

    #[must_use] 
    pub fn as_str(&self) -> String {
        let mut s = String::with_capacity(3);
        s.push(if self.read { 'r' } else { '-' });
        s.push(if self.write { 'w' } else { '-' });
        s.push(if self.execute { 'x' } else { '-' });
        s
    }
}

/// A classified memory region.
#[derive(Debug, Clone)]
pub struct ClassifiedRegion {
    pub range: VaRange,
    pub kind: RegionKind,
    pub perms: RegionPerms,
    pub name: Option<String>,
    /// Entropy of the bytes in this region (0.0–8.0).
    pub entropy: f64,
}

// ─────────────────────────────────────────────────────────────────────────────
// RegionClassifier
// ─────────────────────────────────────────────────────────────────────────────

/// Classifies memory regions based on permissions and optional heuristics.
pub struct RegionClassifier {
    pub pointer_size: u32,
}

impl RegionClassifier {
    #[must_use] 
    pub const fn new(pointer_size: u32) -> Self {
        Self { pointer_size }
    }

    /// Classify a region given its permissions, bytes, and an optional name hint.
    pub fn classify(
        &self,
        range: VaRange,
        perms: RegionPerms,
        bytes: &[u8],
        name: Option<&str>,
    ) -> ClassifiedRegion {
        let entropy = Self::shannon_entropy(bytes);
        let kind = self.infer_kind(&perms, bytes, name, entropy);
        ClassifiedRegion {
            range,
            kind,
            perms,
            name: name.map(str::to_owned),
            entropy,
        }
    }

    fn infer_kind(
        &self,
        perms: &RegionPerms,
        bytes: &[u8],
        name: Option<&str>,
        entropy: f64,
    ) -> RegionKind {
        // Name-based heuristics first.
        if let Some(n) = name {
            let nl = n.to_ascii_lowercase();
            if nl.contains("stack") {
                return RegionKind::Stack;
            }
            if nl.contains("heap") {
                return RegionKind::Heap;
            }
            if nl.contains(".text") || nl.contains(".code") {
                return RegionKind::Code;
            }
            if nl.contains(".rdata") || nl.contains(".rodata") {
                return RegionKind::ReadOnly;
            }
            if nl.contains(".data") || nl.contains(".bss") {
                return RegionKind::Data;
            }
        }
        // Permission-based fallback.
        if perms.execute {
            let _ = entropy;
            return RegionKind::Code;
        }
        if !perms.write && perms.read {
            // PE/ELF magic bytes hint at a code/data image even without exec perms.
            if bytes.starts_with(b"MZ") || bytes.starts_with(b"\x7fELF") {
                return RegionKind::Code;
            }
            return RegionKind::ReadOnly;
        }
        if perms.write && perms.read && !perms.execute {
            // Low entropy writable data → data section; high → heap-like.
            return if entropy > 7.0 {
                RegionKind::Heap
            } else {
                RegionKind::Data
            };
        }
        RegionKind::Unknown
    }

    fn shannon_entropy(data: &[u8]) -> f64 {
        if data.is_empty() {
            return 0.0;
        }
        let mut counts = [0u64; 256];
        for &b in data {
            counts[b as usize] += 1;
        }
        let len = data.len() as f64;
        let mut entropy = 0.0f64;
        for &c in &counts {
            if c > 0 {
                let p = c as f64 / len;
                entropy -= p * p.log2();
            }
        }
        entropy
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// EntropyRegion
// ─────────────────────────────────────────────────────────────────────────────

/// An entropy scan result for a contiguous memory block.
#[derive(Debug, Clone)]
pub struct EntropyRegion {
    pub address: Va,
    pub size: u64,
    pub entropy: f64,
    /// True if entropy exceeds the "packed/encrypted" threshold (≥7.2).
    pub is_suspicious: bool,
}

impl EntropyRegion {
    pub const SUSPICIOUS_THRESHOLD: f64 = 7.2;

    #[must_use] 
    pub fn new(address: Va, bytes: &[u8]) -> Self {
        let entropy = shannon_entropy_bytes(bytes);
        Self {
            address,
            size: bytes.len() as u64,
            entropy,
            is_suspicious: entropy >= Self::SUSPICIOUS_THRESHOLD,
        }
    }
}

/// Public standalone entropy helper used by tests.
#[must_use] 
pub fn shannon_entropy_bytes(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let len = data.len() as f64;
    let mut entropy = 0.0f64;
    for &c in &counts {
        if c > 0 {
            let p = c as f64 / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}

/// Scan a flat byte slice with a given block size and produce [`EntropyRegion`]s.
#[must_use] 
pub fn scan_entropy(base: Va, data: &[u8], block_size: usize) -> Vec<EntropyRegion> {
    if block_size == 0 {
        return vec![];
    }
    let mut result = Vec::with_capacity(data.len().div_ceil(block_size));
    let mut offset = 0usize;
    while offset < data.len() {
        let end = (offset + block_size).min(data.len());
        let block = &data[offset..end];
        let addr = Va(base.0 + offset as u64);
        result.push(EntropyRegion::new(addr, block));
        offset = end;
    }
    result
}

// ─────────────────────────────────────────────────────────────────────────────
// StringScanner
// ─────────────────────────────────────────────────────────────────────────────

/// Encoding of a found string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StringEncoding {
    Ascii,
    Utf16Le,
    Utf16Be,
    Utf8,
    PascalLen1,
    PascalLen4,
}

impl fmt::Display for StringEncoding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Ascii => "ascii",
            Self::Utf16Le => "utf-16le",
            Self::Utf16Be => "utf-16be",
            Self::Utf8 => "utf-8",
            Self::PascalLen1 => "pascal1",
            Self::PascalLen4 => "pascal4",
        };
        write!(f, "{s}")
    }
}

/// A string found in memory.
#[derive(Debug, Clone)]
pub struct FoundString {
    pub address: Va,
    pub length: usize,
    pub encoding: StringEncoding,
    pub value: String,
}

/// Scans flat byte slices for printable strings.
pub struct StringScanner {
    /// Minimum printable string length to report.
    pub min_length: usize,
    /// Whether to scan for UTF-16 LE/BE strings.
    pub scan_utf16: bool,
    /// Whether to scan for Pascal-style length-prefixed strings.
    pub scan_pascal: bool,
}

impl StringScanner {
    #[must_use] 
    pub const fn new(min_length: usize) -> Self {
        Self {
            min_length,
            scan_utf16: true,
            scan_pascal: false,
        }
    }

    /// Scan `data` starting at `base_va`, returning all found strings.
    #[must_use] 
    pub fn scan(&self, base_va: Va, data: &[u8]) -> Vec<FoundString> {
        let mut result = Vec::new();
        self.scan_ascii(base_va, data, &mut result);
        if self.scan_utf16 {
            self.scan_utf16le(base_va, data, &mut result);
        }
        if self.scan_pascal {
            self.scan_pascal1(base_va, data, &mut result);
        }
        result.sort_by_key(|s| s.address.0);
        result
    }

    fn scan_ascii(&self, base: Va, data: &[u8], out: &mut Vec<FoundString>) {
        let mut start: Option<usize> = None;
        for (i, &b) in data.iter().enumerate() {
            let printable = (0x20..0x7F).contains(&b);
            match (printable, start) {
                (true, None) => start = Some(i),
                (false, Some(s)) => {
                    let len = i - s;
                    if len >= self.min_length {
                        let value = String::from_utf8_lossy(&data[s..i]).into_owned();
                        out.push(FoundString {
                            address: Va(base.0 + s as u64),
                            length: len,
                            encoding: StringEncoding::Ascii,
                            value,
                        });
                    }
                    start = None;
                }
                _ => {}
            }
        }
        if let Some(s) = start {
            let len = data.len() - s;
            if len >= self.min_length {
                let value = String::from_utf8_lossy(&data[s..]).into_owned();
                out.push(FoundString {
                    address: Va(base.0 + s as u64),
                    length: len,
                    encoding: StringEncoding::Ascii,
                    value,
                });
            }
        }
    }

    fn scan_utf16le(&self, base: Va, data: &[u8], out: &mut Vec<FoundString>) {
        if data.len() < 2 {
            return;
        }
        let mut start: Option<usize> = None;
        let mut i = 0usize;
        while i + 1 < data.len() {
            let lo = data[i];
            let hi = data[i + 1];
            let ch = u16::from_le_bytes([lo, hi]);
            let printable = (0x20..0x7F).contains(&ch);
            match (printable, start) {
                (true, None) => start = Some(i),
                (false, Some(s)) => {
                    let len = (i - s) / 2;
                    if len >= self.min_length {
                        let chars: Vec<u16> = data[s..i]
                            .chunks_exact(2)
                            .map(|c| u16::from_le_bytes([c[0], c[1]]))
                            .collect();
                        let value = String::from_utf16_lossy(&chars);
                        out.push(FoundString {
                            address: Va(base.0 + s as u64),
                            length: len,
                            encoding: StringEncoding::Utf16Le,
                            value,
                        });
                    }
                    start = None;
                }
                _ => {}
            }
            i += 2;
        }
        // Flush a run that extends to the end of the buffer.
        if let Some(s) = start {
            let len = (i - s) / 2;
            if len >= self.min_length {
                let chars: Vec<u16> = data[s..i]
                    .chunks_exact(2)
                    .map(|c| u16::from_le_bytes([c[0], c[1]]))
                    .collect();
                let value = String::from_utf16_lossy(&chars);
                out.push(FoundString {
                    address: Va(base.0 + s as u64),
                    length: len,
                    encoding: StringEncoding::Utf16Le,
                    value,
                });
            }
        }
    }

    fn scan_pascal1(&self, base: Va, data: &[u8], out: &mut Vec<FoundString>) {
        for i in 0..data.len() {
            let len = data[i] as usize;
            if len < self.min_length {
                continue;
            }
            if i + 1 + len > data.len() {
                continue;
            }
            let slice = &data[i + 1..i + 1 + len];
            if slice.iter().all(|&b| (0x20..0x7F).contains(&b)) {
                let value = String::from_utf8_lossy(slice).into_owned();
                out.push(FoundString {
                    address: Va(base.0 + i as u64),
                    length: len,
                    encoding: StringEncoding::PascalLen1,
                    value,
                });
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PointerScanner
// ─────────────────────────────────────────────────────────────────────────────

/// A pointer found in memory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FoundPointer {
    /// Address where the pointer value was found.
    pub found_at: Va,
    /// Value of the pointer.
    pub target: Va,
    /// True if `target` falls within a known mapped region.
    pub is_valid: bool,
}

/// Scans flat memory for values that look like valid pointers.
pub struct PointerScanner {
    pub pointer_size: u32,
    /// Known valid virtual address ranges used to validate pointer targets.
    pub valid_ranges: Vec<VaRange>,
    pub little_endian: bool,
}

impl PointerScanner {
    #[must_use] 
    pub const fn new(pointer_size: u32, little_endian: bool) -> Self {
        Self {
            pointer_size,
            valid_ranges: Vec::new(),
            little_endian,
        }
    }

    pub fn add_valid_range(&mut self, range: VaRange) {
        self.valid_ranges.push(range);
    }

    /// Scan `data` for pointer-width values; validate them against known ranges.
    #[must_use] 
    pub fn scan(&self, base_va: Va, data: &[u8]) -> Vec<FoundPointer> {
        let step = self.pointer_size as usize / 8;
        if step == 0 || data.len() < step {
            return vec![];
        }
        let mut result = Vec::new();
        let mut i = 0;
        while i + step <= data.len() {
            let target = self.read_ptr(&data[i..i + step]);
            let is_valid = self.valid_ranges.iter().any(|r| r.contains(Va(target)));
            result.push(FoundPointer {
                found_at: Va(base_va.0 + i as u64),
                target: Va(target),
                is_valid,
            });
            i += step;
        }
        result
    }

    /// Scan only returning pointers with valid targets.
    #[must_use] 
    pub fn scan_valid(&self, base_va: Va, data: &[u8]) -> Vec<FoundPointer> {
        self.scan(base_va, data)
            .into_iter()
            .filter(|p| p.is_valid)
            .collect()
    }

    fn read_ptr(&self, bytes: &[u8]) -> u64 {
        match (self.pointer_size, self.little_endian) {
            (32, true) => u64::from(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])),
            (32, false) => u64::from(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])),
            (64, true) => u64::from_le_bytes([
                bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
            ]),
            (64, false) => u64::from_be_bytes([
                bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
            ]),
            _ => 0,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PatternScanner
// ─────────────────────────────────────────────────────────────────────────────

/// A byte pattern with optional wildcard mask.
#[derive(Debug, Clone)]
pub struct BytePattern {
    pub bytes: Vec<u8>,
    /// Same length as `bytes`.  A `0xFF` mask means exact match; `0x00` is wildcard.
    pub mask: Vec<u8>,
    pub name: Option<String>,
}

impl BytePattern {
    /// Create an exact (no-wildcard) pattern.
    pub fn exact(bytes: impl Into<Vec<u8>>) -> Self {
        let b = bytes.into();
        let m = vec![0xFF; b.len()];
        Self {
            bytes: b,
            mask: m,
            name: None,
        }
    }

    /// Create a pattern from a hex string like `"DE ?? BE EF"`.
    #[must_use] 
    pub fn from_hex_str(s: &str) -> Self {
        let mut bytes = Vec::new();
        let mut mask = Vec::new();
        for part in s.split_whitespace() {
            if part == "??" || part == "?" {
                bytes.push(0x00);
                mask.push(0x00);
            } else {
                let b = u8::from_str_radix(part, 16).unwrap_or(0);
                bytes.push(b);
                mask.push(0xFF);
            }
        }
        Self {
            bytes,
            mask,
            name: None,
        }
    }

    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    #[must_use] 
    pub const fn len(&self) -> usize {
        self.bytes.len()
    }
    #[must_use] 
    pub const fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Returns `true` if `data` matches this pattern starting at offset 0.
    #[must_use] 
    pub fn matches_at(&self, data: &[u8]) -> bool {
        if data.len() < self.bytes.len() {
            return false;
        }
        self.bytes
            .iter()
            .zip(&self.mask)
            .zip(data.iter())
            .all(|((b, m), d)| (d & m) == (b & m))
    }
}

/// Match result from the pattern scanner.
#[derive(Debug, Clone)]
pub struct PatternMatch {
    pub address: Va,
    pub pattern_name: Option<String>,
    pub matched_bytes: Vec<u8>,
}

/// Scans memory for a set of byte patterns.
pub struct PatternScanner {
    pub patterns: Vec<BytePattern>,
}

impl PatternScanner {
    #[must_use] 
    pub const fn new() -> Self {
        Self {
            patterns: Vec::new(),
        }
    }

    pub fn add_pattern(&mut self, p: BytePattern) {
        self.patterns.push(p);
    }

    /// Scan `data` for all registered patterns; return all matches.
    #[must_use] 
    pub fn scan(&self, base_va: Va, data: &[u8]) -> Vec<PatternMatch> {
        let mut result = Vec::new();
        for pattern in &self.patterns {
            if pattern.is_empty() {
                continue;
            }
            let plen = pattern.len();
            for i in 0..data.len().saturating_sub(plen - 1) {
                if pattern.matches_at(&data[i..]) {
                    result.push(PatternMatch {
                        address: Va(base_va.0 + i as u64),
                        pattern_name: pattern.name.clone(),
                        matched_bytes: data[i..i + plen].to_vec(),
                    });
                }
            }
        }
        result.sort_by_key(|m| m.address.0);
        result
    }

    /// Scan for a single ad-hoc pattern (convenience wrapper).
    #[must_use] 
    pub fn scan_one(&self, base_va: Va, data: &[u8], pattern: &BytePattern) -> Vec<PatternMatch> {
        if pattern.is_empty() {
            return Vec::new();
        }
        let plen = pattern.len();
        let mut result = Vec::new();
        for i in 0..data.len().saturating_sub(plen - 1) {
            if pattern.matches_at(&data[i..]) {
                result.push(PatternMatch {
                    address: Va(base_va.0 + i as u64),
                    pattern_name: pattern.name.clone(),
                    matched_bytes: data[i..i + plen].to_vec(),
                });
            }
        }
        result.sort_by_key(|m| m.address.0);
        result
    }
}

impl Default for PatternScanner {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MemoryAnalysis
// ─────────────────────────────────────────────────────────────────────────────

/// Configuration for a full memory analysis run.
#[derive(Debug, Clone)]
pub struct MemoryAnalysisOptions {
    pub pointer_size: u32,
    pub little_endian: bool,
    pub entropy_block_size: usize,
    pub min_string_length: usize,
    pub scan_utf16: bool,
    pub scan_pascal: bool,
    pub entropy_suspicious_threshold: f64,
}

impl Default for MemoryAnalysisOptions {
    fn default() -> Self {
        Self {
            pointer_size: 64,
            little_endian: true,
            entropy_block_size: 256,
            min_string_length: 4,
            scan_utf16: true,
            scan_pascal: false,
            entropy_suspicious_threshold: EntropyRegion::SUSPICIOUS_THRESHOLD,
        }
    }
}

/// High-level driver that runs all sub-analyses on a single flat memory region.
pub struct MemoryAnalysis {
    pub options: MemoryAnalysisOptions,
}

impl MemoryAnalysis {
    #[must_use] 
    pub const fn new(options: MemoryAnalysisOptions) -> Self {
        Self { options }
    }

    #[must_use] 
    pub fn with_defaults() -> Self {
        Self::new(MemoryAnalysisOptions::default())
    }

    /// Run all analyses and return a [`MemoryReport`].
    #[must_use] 
    pub fn analyze(
        &self,
        base_va: Va,
        data: &[u8],
        perms: RegionPerms,
        name: Option<&str>,
        patterns: &[BytePattern],
        valid_ranges: &[VaRange],
    ) -> MemoryReport {
        let range = VaRange::new(base_va, Va(base_va.0 + data.len() as u64));

        // Classify.
        let classifier = RegionClassifier::new(self.options.pointer_size);
        let classified = classifier.classify(range, perms, data, name);

        // Entropy blocks.
        let entropy_regions = scan_entropy(base_va, data, self.options.entropy_block_size);
        // Count up-front instead of holding borrows into `entropy_regions`,
        // so the vector can be moved into `MemoryReport` below.
        let suspicious_entropy_count: usize = entropy_regions
            .iter()
            .filter(|r| r.entropy >= self.options.entropy_suspicious_threshold)
            .count();

        // Strings.
        let mut str_scanner = StringScanner::new(self.options.min_string_length);
        str_scanner.scan_utf16 = self.options.scan_utf16;
        str_scanner.scan_pascal = self.options.scan_pascal;
        let strings = str_scanner.scan(base_va, data);

        // Pointers.
        let mut ptr_scanner =
            PointerScanner::new(self.options.pointer_size, self.options.little_endian);
        for r in valid_ranges {
            ptr_scanner.add_valid_range(*r);
        }
        let valid_pointers = ptr_scanner.scan_valid(base_va, data);

        // Patterns.
        let mut pat_scanner = PatternScanner::new();
        for p in patterns {
            pat_scanner.add_pattern(p.clone());
        }
        let pattern_matches = pat_scanner.scan(base_va, data);

        MemoryReport {
            range,
            classified_region: classified,
            entropy_regions,
            suspicious_entropy_count,
            strings,
            valid_pointers,
            pattern_matches,
            total_bytes: data.len() as u64,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MemoryReport
// ─────────────────────────────────────────────────────────────────────────────

/// Aggregated results from a full memory analysis pass.
#[derive(Debug)]
pub struct MemoryReport {
    pub range: VaRange,
    pub classified_region: ClassifiedRegion,
    pub entropy_regions: Vec<EntropyRegion>,
    pub suspicious_entropy_count: usize,
    pub strings: Vec<FoundString>,
    pub valid_pointers: Vec<FoundPointer>,
    pub pattern_matches: Vec<PatternMatch>,
    pub total_bytes: u64,
}

impl MemoryReport {
    #[must_use] 
    pub fn avg_entropy(&self) -> f64 {
        if self.entropy_regions.is_empty() {
            return 0.0;
        }
        let sum: f64 = self.entropy_regions.iter().map(|e| e.entropy).sum();
        sum / self.entropy_regions.len() as f64
    }

    #[must_use] 
    pub const fn is_likely_packed(&self) -> bool {
        self.suspicious_entropy_count > 0
    }

    #[must_use] 
    pub fn ascii_string_count(&self) -> usize {
        self.strings
            .iter()
            .filter(|s| s.encoding == StringEncoding::Ascii)
            .count()
    }

    #[must_use] 
    pub fn summary(&self) -> String {
        format!(
            "MemoryReport {{ range={:?}, kind={}, strings={}, ptrs={}, patterns={}, suspicious_entropy={} }}",
            (self.range.start.0, self.range.end.0),
            self.classified_region.kind,
            self.strings.len(),
            self.valid_pointers.len(),
            self.pattern_matches.len(),
            self.suspicious_entropy_count,
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Va ────────────────────────────────────────────────────────────────────

    #[test]
    fn va_new_and_display() {
        let v = Va::new(0x1000);
        assert_eq!(v.as_u64(), 0x1000);
        assert!(v.to_string().contains("0x0000000000001000"));
    }

    #[test]
    fn va_checked_add_overflow() {
        let v = Va::new(u64::MAX);
        assert!(v.checked_add(1).is_none());
    }

    #[test]
    fn va_wrapping_add() {
        let v = Va::new(u64::MAX);
        assert_eq!(v.wrapping_add(1).as_u64(), 0);
    }

    #[test]
    fn va_offset_from() {
        let base = Va::new(0x1000);
        let v = Va::new(0x1010);
        assert_eq!(v.offset_from(base), Some(0x10));
        assert_eq!(base.offset_from(v), None);
    }

    // ── VaRange ───────────────────────────────────────────────────────────────

    #[test]
    fn va_range_len() {
        let r = VaRange::new(Va(0x1000), Va(0x2000));
        assert_eq!(r.len(), 0x1000);
    }

    #[test]
    fn va_range_empty() {
        let r = VaRange::new(Va(0x1000), Va(0x1000));
        assert!(r.is_empty());
    }

    #[test]
    fn va_range_contains() {
        let r = VaRange::new(Va(0x1000), Va(0x2000));
        assert!(r.contains(Va(0x1500)));
        assert!(!r.contains(Va(0x2000)));
        assert!(!r.contains(Va(0x0FFF)));
    }

    #[test]
    fn va_range_overlaps() {
        let r1 = VaRange::new(Va(0x1000), Va(0x2000));
        let r2 = VaRange::new(Va(0x1800), Va(0x3000));
        let r3 = VaRange::new(Va(0x3000), Va(0x4000));
        assert!(r1.overlaps(&r2));
        assert!(!r1.overlaps(&r3));
    }

    // ── RegionKind ────────────────────────────────────────────────────────────

    #[test]
    fn region_kind_display() {
        assert_eq!(RegionKind::Code.to_string(), "code");
        assert_eq!(RegionKind::Stack.to_string(), "stack");
        assert_eq!(RegionKind::Unknown.to_string(), "unknown");
    }

    // ── RegionPerms ───────────────────────────────────────────────────────────

    #[test]
    fn region_perms_as_str() {
        assert_eq!(RegionPerms::rx().as_str(), "r-x");
        assert_eq!(RegionPerms::rw().as_str(), "rw-");
        assert_eq!(RegionPerms::rwx().as_str(), "rwx");
    }

    // ── RegionClassifier ──────────────────────────────────────────────────────

    #[test]
    fn classify_code_by_name() {
        let classifier = RegionClassifier::new(64);
        let bytes = vec![0x55u8, 0x48, 0x89, 0xE5]; // x86-64 prologue
        let range = VaRange::new(Va(0x1000), Va(0x1004));
        let cr = classifier.classify(range, RegionPerms::rx(), &bytes, Some(".text"));
        assert_eq!(cr.kind, RegionKind::Code);
    }

    #[test]
    fn classify_stack_by_name() {
        let classifier = RegionClassifier::new(64);
        let bytes = vec![0u8; 64];
        let range = VaRange::new(Va(0xFFFF0000), Va(0xFFFF0040));
        let cr = classifier.classify(range, RegionPerms::rw(), &bytes, Some("stack"));
        assert_eq!(cr.kind, RegionKind::Stack);
    }

    #[test]
    fn classify_readonly_by_perms() {
        let classifier = RegionClassifier::new(64);
        let bytes = b"Hello World!!!!".to_vec();
        let range = VaRange::new(Va(0x4000), Va(0x4010));
        let cr = classifier.classify(range, RegionPerms::ro(), &bytes, None);
        assert_eq!(cr.kind, RegionKind::ReadOnly);
    }

    #[test]
    fn classify_data_by_perms() {
        let classifier = RegionClassifier::new(64);
        let bytes = vec![0u8; 64];
        let range = VaRange::new(Va(0x5000), Va(0x5040));
        let cr = classifier.classify(range, RegionPerms::rw(), &bytes, None);
        assert_eq!(cr.kind, RegionKind::Data);
    }

    #[test]
    fn classifier_entropy_stored() {
        let classifier = RegionClassifier::new(64);
        let bytes: Vec<u8> = (0u8..=255).collect();
        let range = VaRange::new(Va(0x1000), Va(0x1100));
        let cr = classifier.classify(range, RegionPerms::ro(), &bytes, None);
        assert!((cr.entropy - 8.0).abs() < 0.1);
    }

    // ── EntropyRegion ─────────────────────────────────────────────────────────

    #[test]
    fn entropy_region_zero_bytes() {
        let r = EntropyRegion::new(Va(0x1000), &[0u8; 256]);
        assert!((r.entropy - 0.0).abs() < 1e-9);
        assert!(!r.is_suspicious);
    }

    #[test]
    fn entropy_region_random_bytes() {
        let data: Vec<u8> = (0u8..=255).collect();
        let r = EntropyRegion::new(Va(0x1000), &data);
        assert!((r.entropy - 8.0).abs() < 0.1);
        assert!(r.is_suspicious);
    }

    #[test]
    fn scan_entropy_block_count() {
        let data = vec![0u8; 1024];
        let blocks = scan_entropy(Va(0x1000), &data, 256);
        assert_eq!(blocks.len(), 4);
    }

    #[test]
    fn scan_entropy_partial_last_block() {
        let data = vec![0u8; 300];
        let blocks = scan_entropy(Va(0x1000), &data, 256);
        assert_eq!(blocks.len(), 2);
        assert_eq!(blocks[1].size, 44);
    }

    // ── StringScanner ─────────────────────────────────────────────────────────

    #[test]
    fn string_scanner_finds_ascii() {
        let data = b"Hello World!\x00\x01\x02";
        let scanner = StringScanner::new(4);
        let found = scanner.scan(Va(0x1000), data);
        let ascii: Vec<&FoundString> = found
            .iter()
            .filter(|s| s.encoding == StringEncoding::Ascii)
            .collect();
        assert!(!ascii.is_empty());
        let values: Vec<&str> = ascii.iter().map(|s| s.value.as_str()).collect();
        assert!(values.iter().any(|v| v.contains("Hello World")));
    }

    #[test]
    fn string_scanner_min_length_filter() {
        let data = b"ab\x00Hello\x00";
        let scanner = StringScanner::new(5);
        let found = scanner.scan(Va(0x1000), data);
        assert!(!found.iter().any(|s| s.value == "ab"));
    }

    #[test]
    fn string_scanner_utf16le() {
        // "AB" in UTF-16 LE
        let _data: Vec<u8> = b"AB\x00\x00HELLO\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00".to_vec();
        let mut data16: Vec<u8> = Vec::new();
        for b in b"HELLO" {
            data16.push(*b);
            data16.push(0x00);
        }
        let mut scanner = StringScanner::new(4);
        scanner.scan_utf16 = true;
        let found = scanner.scan(Va(0x1000), &data16);
        let utf16: Vec<&FoundString> = found
            .iter()
            .filter(|s| s.encoding == StringEncoding::Utf16Le)
            .collect();
        assert!(!utf16.is_empty());
    }

    #[test]
    fn string_scanner_no_utf16_when_disabled() {
        let mut data16: Vec<u8> = Vec::new();
        for b in b"HELLO" {
            data16.push(*b);
            data16.push(0x00);
        }
        let mut scanner = StringScanner::new(4);
        scanner.scan_utf16 = false;
        let found = scanner.scan(Va(0x1000), &data16);
        assert!(!found.iter().any(|s| s.encoding == StringEncoding::Utf16Le));
    }

    #[test]
    fn string_scanner_pascal() {
        let mut data = vec![0x05u8];
        data.extend_from_slice(b"Hello");
        let mut scanner = StringScanner::new(4);
        scanner.scan_pascal = true;
        let found = scanner.scan(Va(0x1000), &data);
        let pascal: Vec<&FoundString> = found
            .iter()
            .filter(|s| s.encoding == StringEncoding::PascalLen1)
            .collect();
        assert!(!pascal.is_empty());
        assert_eq!(pascal[0].value, "Hello");
    }

    #[test]
    fn string_scanner_sorted_by_address() {
        let mut data = vec![0u8; 32];
        data[0..5].copy_from_slice(b"aaaaa");
        data[10..15].copy_from_slice(b"bbbbb");
        let scanner = StringScanner::new(4);
        let found = scanner.scan(Va(0x1000), &data);
        let addrs: Vec<u64> = found.iter().map(|s| s.address.0).collect();
        let mut sorted = addrs.clone();
        sorted.sort();
        assert_eq!(addrs, sorted);
    }

    // ── PointerScanner ────────────────────────────────────────────────────────

    #[test]
    fn pointer_scanner_64bit_le() {
        let mut scanner = PointerScanner::new(64, true);
        scanner.add_valid_range(VaRange::new(Va(0x400000), Va(0x500000)));
        let target: u64 = 0x401234;
        let data = target.to_le_bytes();
        let ptrs = scanner.scan(Va(0x2000), &data);
        assert_eq!(ptrs.len(), 1);
        assert_eq!(ptrs[0].target.as_u64(), target);
        assert!(ptrs[0].is_valid);
    }

    #[test]
    fn pointer_scanner_invalid_target() {
        let mut scanner = PointerScanner::new(64, true);
        scanner.add_valid_range(VaRange::new(Va(0x400000), Va(0x500000)));
        let target: u64 = 0xDEADBEEFCAFEBABE;
        let data = target.to_le_bytes();
        let ptrs = scanner.scan(Va(0x2000), &data);
        assert_eq!(ptrs.len(), 1);
        assert!(!ptrs[0].is_valid);
    }

    #[test]
    fn pointer_scanner_32bit_be() {
        let scanner = PointerScanner::new(32, false);
        let target: u32 = 0x00401000;
        let data = target.to_be_bytes();
        let ptrs = scanner.scan(Va(0x2000), &data);
        assert_eq!(ptrs[0].target.as_u64(), target as u64);
    }

    #[test]
    fn pointer_scanner_scan_valid_filters() {
        let mut scanner = PointerScanner::new(64, true);
        scanner.add_valid_range(VaRange::new(Va(0x400000), Va(0x500000)));
        let mut data = Vec::new();
        data.extend_from_slice(&0x401234u64.to_le_bytes()); // valid
        data.extend_from_slice(&0xDEADBEEFu64.to_le_bytes()); // invalid
        let valid = scanner.scan_valid(Va(0x2000), &data);
        assert_eq!(valid.len(), 1);
        assert_eq!(valid[0].target.as_u64(), 0x401234);
    }

    // ── BytePattern ───────────────────────────────────────────────────────────

    #[test]
    fn byte_pattern_exact_match() {
        let p = BytePattern::exact(vec![0xDE, 0xAD, 0xBE, 0xEF]);
        assert!(p.matches_at(&[0xDE, 0xAD, 0xBE, 0xEF, 0x00]));
        assert!(!p.matches_at(&[0xDE, 0xAD, 0xBE, 0xFF]));
    }

    #[test]
    fn byte_pattern_wildcard() {
        let p = BytePattern::from_hex_str("DE ?? BE ??");
        assert!(p.matches_at(&[0xDE, 0x00, 0xBE, 0xFF]));
        assert!(p.matches_at(&[0xDE, 0xFF, 0xBE, 0x00]));
        assert!(!p.matches_at(&[0xFF, 0x00, 0xBE, 0xFF]));
    }

    #[test]
    fn byte_pattern_from_hex_str() {
        let p = BytePattern::from_hex_str("90 90 90");
        assert_eq!(p.len(), 3);
        assert!(p.matches_at(&[0x90, 0x90, 0x90]));
    }

    #[test]
    fn byte_pattern_with_name() {
        let p = BytePattern::exact(vec![0x90]).with_name("nop");
        assert_eq!(p.name.as_deref(), Some("nop"));
    }

    // ── PatternScanner ────────────────────────────────────────────────────────

    #[test]
    fn pattern_scanner_finds_match() {
        let mut scanner = PatternScanner::new();
        scanner.add_pattern(BytePattern::exact(vec![0xDE, 0xAD]).with_name("marker"));
        let data = [0x00u8, 0x00, 0xDE, 0xAD, 0x00, 0xDE, 0xAD];
        let matches = scanner.scan(Va(0x1000), &data);
        assert_eq!(matches.len(), 2);
        assert_eq!(matches[0].address.as_u64(), 0x1002);
        assert_eq!(matches[1].address.as_u64(), 0x1005);
    }

    #[test]
    fn pattern_scanner_no_match() {
        let mut scanner = PatternScanner::new();
        scanner.add_pattern(BytePattern::exact(vec![0xFF, 0xFF]));
        let data = [0x00u8; 16];
        assert!(scanner.scan(Va(0x1000), &data).is_empty());
    }

    #[test]
    fn pattern_scanner_wildcard_match() {
        let mut scanner = PatternScanner::new();
        scanner.add_pattern(BytePattern::from_hex_str("55 ?? 89 E5"));
        let data = [0x55u8, 0x48, 0x89, 0xE5];
        let m = scanner.scan(Va(0x1000), &data);
        assert_eq!(m.len(), 1);
    }

    #[test]
    fn pattern_scanner_multiple_patterns() {
        let mut scanner = PatternScanner::new();
        scanner.add_pattern(BytePattern::exact(vec![0xCC]).with_name("int3"));
        scanner.add_pattern(BytePattern::exact(vec![0x90]).with_name("nop"));
        let data = [0xCC, 0x90, 0xCC];
        let m = scanner.scan(Va(0x0), &data);
        assert_eq!(m.len(), 3);
    }

    // ── MemoryAnalysis ────────────────────────────────────────────────────────

    #[test]
    fn memory_analysis_basic() {
        let analysis = MemoryAnalysis::with_defaults();
        let mut data = vec![0u8; 256];
        data[0..12].copy_from_slice(b"Hello World!");
        let report = analysis.analyze(
            Va(0x1000),
            &data,
            RegionPerms::ro(),
            Some(".rodata"),
            &[],
            &[],
        );
        assert_eq!(report.classified_region.kind, RegionKind::ReadOnly);
        assert!(!report.strings.is_empty());
    }

    #[test]
    fn memory_analysis_entropy_blocks() {
        let analysis = MemoryAnalysis::with_defaults();
        let data: Vec<u8> = (0u8..=255).collect();
        let report = analysis.analyze(Va(0x1000), &data, RegionPerms::ro(), None, &[], &[]);
        assert!(!report.entropy_regions.is_empty());
    }

    #[test]
    fn memory_analysis_pattern_match() {
        let analysis = MemoryAnalysis::with_defaults();
        let data = [0x55u8, 0x48, 0x89, 0xE5];
        let pattern = BytePattern::from_hex_str("55 48 89 E5");
        let report = analysis.analyze(
            Va(0x1000),
            &data,
            RegionPerms::rx(),
            Some(".text"),
            &[pattern],
            &[],
        );
        assert_eq!(report.pattern_matches.len(), 1);
    }

    #[test]
    fn memory_report_summary_not_empty() {
        let analysis = MemoryAnalysis::with_defaults();
        let data = vec![0u8; 64];
        let report = analysis.analyze(Va(0x1000), &data, RegionPerms::rw(), None, &[], &[]);
        assert!(!report.summary().is_empty());
    }

    #[test]
    fn memory_report_avg_entropy() {
        let analysis = MemoryAnalysis::with_defaults();
        let data = vec![0u8; 256];
        let report = analysis.analyze(Va(0x1000), &data, RegionPerms::ro(), None, &[], &[]);
        assert!((report.avg_entropy() - 0.0).abs() < 1e-6);
    }

    #[test]
    fn memory_report_is_likely_packed() {
        let analysis = MemoryAnalysis::new(MemoryAnalysisOptions {
            entropy_block_size: 256,
            ..Default::default()
        });
        let data: Vec<u8> = (0u8..=255).collect();
        let report = analysis.analyze(Va(0x1000), &data, RegionPerms::rx(), None, &[], &[]);
        assert!(report.is_likely_packed());
    }

    #[test]
    fn memory_report_ascii_string_count() {
        let analysis = MemoryAnalysis::with_defaults();
        let data = b"Hello World! Another string here.\x00\x00\x00".to_vec();
        let report = analysis.analyze(Va(0x1000), &data, RegionPerms::ro(), None, &[], &[]);
        assert!(report.ascii_string_count() > 0);
    }

    #[test]
    fn memory_report_valid_pointers() {
        let analysis = MemoryAnalysis::new(MemoryAnalysisOptions {
            pointer_size: 64,
            ..Default::default()
        });
        let valid_range = VaRange::new(Va(0x400000), Va(0x500000));
        let target: u64 = 0x401234;
        let data = target.to_le_bytes().to_vec();
        let report = analysis.analyze(
            Va(0x2000),
            &data,
            RegionPerms::rw(),
            None,
            &[],
            &[valid_range],
        );
        assert_eq!(report.valid_pointers.len(), 1);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MemoryDiffAnalysis — diff two memory regions byte-by-byte
// ─────────────────────────────────────────────────────────────────────────────

/// A span of changed bytes in a memory diff.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiffSpan {
    /// Start virtual address of the changed range.
    pub start: Va,
    /// Original bytes.
    pub old_bytes: Vec<u8>,
    /// New bytes.
    pub new_bytes: Vec<u8>,
}

impl DiffSpan {
    /// Length of this span in bytes.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.old_bytes.len()
    }
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.old_bytes.is_empty()
    }
}

/// Computes a minimal set of changed spans between two equal-length byte slices.
#[must_use]
pub fn diff_regions(base: Va, before: &[u8], after: &[u8]) -> Vec<DiffSpan> {
    assert_eq!(
        before.len(),
        after.len(),
        "diff_regions: slices must be the same length"
    );
    let mut spans: Vec<DiffSpan> = Vec::new();
    let mut i = 0usize;
    while i < before.len() {
        if before[i] == after[i] {
            i += 1;
            continue;
        }
        let start = i;
        while i < before.len() && before[i] != after[i] {
            i += 1;
        }
        spans.push(DiffSpan {
            start: Va(base.0 + start as u64),
            old_bytes: before[start..i].to_vec(),
            new_bytes: after[start..i].to_vec(),
        });
    }
    spans
}

// ─────────────────────────────────────────────────────────────────────────────
// MemoryStatistics — aggregate stats over a memory layout
// ─────────────────────────────────────────────────────────────────────────────

/// High-level statistics about a memory layout.
#[derive(Debug, Clone, Default)]
pub struct MemoryStatistics {
    pub total_bytes: u64,
    pub zero_bytes: u64,
    pub non_zero_bytes: u64,
    pub min_entropy_block_addr: Option<Va>,
    pub max_entropy_block_addr: Option<Va>,
    pub min_entropy: f64,
    pub max_entropy: f64,
}

impl MemoryStatistics {
    /// Compute statistics for a byte slice loaded at `base`.
    #[must_use]
    pub fn compute(base: Va, data: &[u8], block_size: usize) -> Self {
        if data.is_empty() {
            return Self::default();
        }
        let zero_bytes = data.iter().filter(|&&b| b == 0).count() as u64;
        let total_bytes = data.len() as u64;

        let mut min_ent = f64::MAX;
        let mut max_ent = f64::MIN;
        let mut min_addr = Va(0);
        let mut max_addr = Va(0);

        for (chunk_idx, chunk) in data.chunks(block_size.max(1)).enumerate() {
            let ent = entropy(chunk);
            let addr = Va(base.0 + (chunk_idx * block_size) as u64);
            if ent < min_ent {
                min_ent = ent;
                min_addr = addr;
            }
            if ent > max_ent {
                max_ent = ent;
                max_addr = addr;
            }
        }

        Self {
            total_bytes,
            zero_bytes,
            non_zero_bytes: total_bytes - zero_bytes,
            min_entropy_block_addr: Some(min_addr),
            max_entropy_block_addr: Some(max_addr),
            min_entropy: min_ent,
            max_entropy: max_ent,
        }
    }

    /// Fraction of non-zero bytes.
    #[must_use]
    pub fn non_zero_fraction(&self) -> f64 {
        if self.total_bytes == 0 {
            return 0.0;
        }
        self.non_zero_bytes as f64 / self.total_bytes as f64
    }

    /// Fraction of zero bytes.
    #[must_use]
    pub fn zero_fraction(&self) -> f64 {
        1.0 - self.non_zero_fraction()
    }
}

fn entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut freq = [0u64; 256];
    for &b in data {
        freq[b as usize] += 1;
    }
    let len = data.len() as f64;
    let mut ent = 0.0f64;
    for &f in &freq {
        if f > 0 {
            let p = f as f64 / len;
            ent -= p * p.log2();
        }
    }
    ent
}

// ─────────────────────────────────────────────────────────────────────────────
// Yara-like byte pattern matcher
// ─────────────────────────────────────────────────────────────────────────────

/// A simple byte-pattern matcher supporting wildcard bytes (`None`).
#[derive(Debug, Clone)]
pub struct BytePatternMatcher {
    pattern: Vec<Option<u8>>,
}

impl BytePatternMatcher {
    /// Parse a hex-string pattern where `??` is a wildcard byte.
    /// Example: `"DE AD ?? EF"`
    #[must_use]
    pub fn parse(pattern_str: &str) -> Self {
        let pattern = pattern_str
            .split_whitespace()
            .map(|tok| {
                if tok == "??" {
                    None
                } else {
                    u8::from_str_radix(tok, 16).ok()
                }
            })
            .collect();
        Self { pattern }
    }

    /// Find all occurrences in `data` and return their byte offsets.
    #[must_use]
    pub fn find_all(&self, data: &[u8]) -> Vec<usize> {
        if self.pattern.is_empty() {
            return vec![];
        }
        let pat_len = self.pattern.len();
        let mut results = Vec::new();
        if data.len() < pat_len {
            return results;
        }
        'outer: for i in 0..=(data.len() - pat_len) {
            for (j, &pat_byte) in self.pattern.iter().enumerate() {
                if let Some(b) = pat_byte
                    && data[i + j] != b {
                        continue 'outer;
                    }
            }
            results.push(i);
        }
        results
    }

    /// Pattern length in bytes.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.pattern.len()
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.pattern.is_empty()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Additional tests for the new utilities
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod extended_tests {
    use super::*;

    // ── diff_regions ─────────────────────────────────────────────────────────

    #[test]
    fn diff_identical_produces_no_spans() {
        let a = vec![0u8; 16];
        let b = vec![0u8; 16];
        let spans = diff_regions(Va(0x1000), &a, &b);
        assert!(spans.is_empty());
    }

    #[test]
    fn diff_single_byte_change() {
        let a = vec![0u8; 8];
        let mut b = vec![0u8; 8];
        b[4] = 0xFF;
        let spans = diff_regions(Va(0x1000), &a, &b);
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].start, Va(0x1004));
        assert_eq!(spans[0].old_bytes, &[0]);
        assert_eq!(spans[0].new_bytes, &[0xFF]);
    }

    #[test]
    fn diff_multiple_changed_regions() {
        let a = vec![0u8; 16];
        let mut b = vec![0u8; 16];
        b[0] = 1;
        b[1] = 2;
        b[8] = 3;
        let spans = diff_regions(Va(0), &a, &b);
        assert_eq!(spans.len(), 2, "expected 2 changed spans: got {spans:?}");
    }

    #[test]
    fn diff_span_len() {
        let span = DiffSpan {
            start: Va(0),
            old_bytes: vec![0u8; 4],
            new_bytes: vec![1u8; 4],
        };
        assert_eq!(span.len(), 4);
        assert!(!span.is_empty());
    }

    // ── MemoryStatistics ─────────────────────────────────────────────────────

    #[test]
    fn stats_all_zeros() {
        let data = vec![0u8; 256];
        let s = MemoryStatistics::compute(Va(0), &data, 64);
        assert_eq!(s.total_bytes, 256);
        assert_eq!(s.zero_bytes, 256);
        assert!((s.min_entropy - 0.0).abs() < 1e-9);
    }

    #[test]
    fn stats_all_same_nonzero() {
        let data = vec![0xAAu8; 128];
        let s = MemoryStatistics::compute(Va(0), &data, 64);
        assert_eq!(s.non_zero_bytes, 128);
        assert!((s.min_entropy - 0.0).abs() < 1e-9);
    }

    #[test]
    fn stats_non_zero_fraction() {
        let data = vec![0u8, 1, 0, 1, 0, 1, 0, 1];
        let s = MemoryStatistics::compute(Va(0), &data, 4);
        assert!((s.non_zero_fraction() - 0.5).abs() < 1e-9);
    }

    #[test]
    fn stats_empty_data() {
        let s = MemoryStatistics::compute(Va(0), &[], 64);
        assert_eq!(s.total_bytes, 0);
    }

    // ── BytePatternMatcher ───────────────────────────────────────────────────

    #[test]
    fn pattern_matcher_exact_match() {
        let m = BytePatternMatcher::parse("DE AD BE EF");
        let data = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x00];
        let hits = m.find_all(&data);
        assert_eq!(hits, vec![0]);
    }

    #[test]
    fn pattern_matcher_wildcard() {
        let m = BytePatternMatcher::parse("DE ?? BE EF");
        let data = vec![0xDE, 0xFF, 0xBE, 0xEF];
        let hits = m.find_all(&data);
        assert_eq!(hits, vec![0]);
    }

    #[test]
    fn pattern_matcher_multiple_hits() {
        let m = BytePatternMatcher::parse("CC CC");
        let data = vec![0xCC, 0xCC, 0x00, 0xCC, 0xCC];
        let hits = m.find_all(&data);
        assert_eq!(hits.len(), 2);
    }

    #[test]
    fn pattern_matcher_no_hit() {
        let m = BytePatternMatcher::parse("FF FF FF FF");
        let data = vec![0x00u8; 64];
        assert!(m.find_all(&data).is_empty());
    }

    #[test]
    fn pattern_matcher_empty_pattern() {
        let m = BytePatternMatcher::parse("");
        let data = vec![0xAAu8; 8];
        assert!(m.find_all(&data).is_empty());
        assert!(m.is_empty());
    }

    #[test]
    fn pattern_matcher_pattern_larger_than_data() {
        let m = BytePatternMatcher::parse("DE AD BE EF 00 11 22 33");
        let data = vec![0xDE, 0xAD];
        assert!(m.find_all(&data).is_empty());
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MemorySegmentIndex — build an address-range index over memory segments
// ─────────────────────────────────────────────────────────────────────────────

/// One indexed segment.
#[derive(Debug, Clone)]
pub struct IndexedSegment {
    pub start: Va,
    pub end: Va,
    pub name: Option<String>,
    pub data: Vec<u8>,
}

impl IndexedSegment {
    #[must_use]
    pub const fn new(start: Va, data: Vec<u8>, name: Option<String>) -> Self {
        let end = Va(start.0 + data.len() as u64);
        Self {
            start,
            end,
            name,
            data,
        }
    }

    #[must_use]
    pub const fn contains(&self, addr: Va) -> bool {
        addr.0 >= self.start.0 && addr.0 < self.end.0
    }

    #[must_use]
    pub const fn size(&self) -> usize {
        self.data.len()
    }

    /// Read bytes at `addr` for `len` bytes, or `None` if out of range.
    #[must_use]
    pub fn read(&self, addr: Va, len: usize) -> Option<&[u8]> {
        if !self.contains(addr) {
            return None;
        }
        let off = (addr.0 - self.start.0) as usize;
        if off + len > self.data.len() {
            return None;
        }
        Some(&self.data[off..off + len])
    }
}

/// An index over multiple `IndexedSegment`s allowing fast address-based lookup.
#[derive(Debug, Default)]
pub struct MemorySegmentIndex {
    segments: Vec<IndexedSegment>,
}

impl MemorySegmentIndex {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&mut self, seg: IndexedSegment) {
        self.segments.push(seg);
        // Keep sorted by start address for binary search.
        self.segments.sort_by_key(|s| s.start.0);
    }

    /// Find the segment containing `addr`.
    #[must_use]
    pub fn find(&self, addr: Va) -> Option<&IndexedSegment> {
        // Binary search for the last segment with start ≤ addr.
        let idx = self.segments.partition_point(|s| s.start.0 <= addr.0);
        if idx == 0 {
            return None;
        }
        let seg = &self.segments[idx - 1];
        if seg.contains(addr) { Some(seg) } else { None }
    }

    /// Read bytes at `addr` from whichever segment contains it.
    #[must_use]
    pub fn read(&self, addr: Va, len: usize) -> Option<&[u8]> {
        self.find(addr)?.read(addr, len)
    }

    /// Number of segments.
    #[must_use]
    pub const fn segment_count(&self) -> usize {
        self.segments.len()
    }

    /// Total mapped bytes.
    #[must_use]
    pub fn total_mapped(&self) -> usize {
        self.segments.iter().map(IndexedSegment::size).sum()
    }

    /// Check if `addr` is mapped.
    #[must_use]
    pub fn is_mapped(&self, addr: Va) -> bool {
        self.find(addr).is_some()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MemoryRegionMerger — merge adjacent/overlapping regions
// ─────────────────────────────────────────────────────────────────────────────

/// A lightweight memory region descriptor for merging purposes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MergeableRegion {
    pub start: u64,
    pub end: u64, // exclusive
    pub label: Option<String>,
}

impl MergeableRegion {
    #[must_use]
    pub const fn new(start: u64, end: u64) -> Self {
        Self {
            start,
            end,
            label: None,
        }
    }

    #[must_use]
    pub const fn len(&self) -> u64 {
        self.end.saturating_sub(self.start)
    }

    /// Returns `true` when [`len`](Self::len) is zero.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len() == 0
    }

    #[must_use]
    pub const fn overlaps(&self, other: &Self) -> bool {
        self.start < other.end && other.start < self.end
    }

    #[must_use]
    pub const fn adjacent(&self, other: &Self) -> bool {
        self.end == other.start || other.end == self.start
    }
}

/// Merge overlapping or adjacent regions into a minimal set.
#[must_use]
pub fn merge_regions(mut regions: Vec<MergeableRegion>) -> Vec<MergeableRegion> {
    if regions.is_empty() {
        return regions;
    }
    regions.sort_by_key(|r| (r.start, r.end));
    let mut merged: Vec<MergeableRegion> = vec![regions[0].clone()];
    for r in regions.into_iter().skip(1) {
        let last = merged.last_mut().unwrap();
        if last.end >= r.start {
            // Overlap or touching — extend.
            last.end = last.end.max(r.end);
        } else {
            merged.push(r);
        }
    }
    merged
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests for MemorySegmentIndex and MemoryRegionMerger
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod segment_tests {
    use super::*;

    #[test]
    fn indexed_segment_contains() {
        let seg = IndexedSegment::new(Va(0x1000), vec![0u8; 0x100], None);
        assert!(seg.contains(Va(0x1000)));
        assert!(seg.contains(Va(0x10FF)));
        assert!(!seg.contains(Va(0x1100)));
    }

    #[test]
    fn indexed_segment_read() {
        let mut data = vec![0u8; 16];
        data[4] = 0xDE;
        data[5] = 0xAD;
        let seg = IndexedSegment::new(Va(0x1000), data, None);
        let bytes = seg.read(Va(0x1004), 2).unwrap();
        assert_eq!(bytes, &[0xDE, 0xAD]);
    }

    #[test]
    fn indexed_segment_read_out_of_range() {
        let seg = IndexedSegment::new(Va(0x1000), vec![0u8; 8], None);
        assert!(seg.read(Va(0x2000), 4).is_none());
    }

    #[test]
    fn segment_index_find() {
        let mut idx = MemorySegmentIndex::new();
        idx.add(IndexedSegment::new(
            Va(0x1000),
            vec![0u8; 0x100],
            Some("seg0".into()),
        ));
        idx.add(IndexedSegment::new(
            Va(0x2000),
            vec![0u8; 0x100],
            Some("seg1".into()),
        ));
        assert!(idx.find(Va(0x1050)).is_some());
        assert!(idx.find(Va(0x2050)).is_some());
        assert!(idx.find(Va(0x3000)).is_none());
    }

    #[test]
    fn segment_index_read() {
        let mut idx = MemorySegmentIndex::new();
        let mut data = vec![0u8; 8];
        data[0] = 0xAB;
        idx.add(IndexedSegment::new(Va(0x1000), data, None));
        let bytes = idx.read(Va(0x1000), 1).unwrap();
        assert_eq!(bytes, &[0xAB]);
    }

    #[test]
    fn segment_index_is_mapped() {
        let mut idx = MemorySegmentIndex::new();
        idx.add(IndexedSegment::new(Va(0x1000), vec![0u8; 8], None));
        assert!(idx.is_mapped(Va(0x1000)));
        assert!(!idx.is_mapped(Va(0x9000)));
    }

    #[test]
    fn segment_index_total_mapped() {
        let mut idx = MemorySegmentIndex::new();
        idx.add(IndexedSegment::new(Va(0x1000), vec![0u8; 0x100], None));
        idx.add(IndexedSegment::new(Va(0x2000), vec![0u8; 0x200], None));
        assert_eq!(idx.total_mapped(), 0x300);
    }

    #[test]
    fn merge_regions_no_overlap() {
        let rs = vec![MergeableRegion::new(0, 10), MergeableRegion::new(20, 30)];
        let merged = merge_regions(rs);
        assert_eq!(merged.len(), 2);
    }

    #[test]
    fn merge_regions_overlap() {
        let rs = vec![MergeableRegion::new(0, 15), MergeableRegion::new(10, 25)];
        let merged = merge_regions(rs);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].end, 25);
    }

    #[test]
    fn merge_regions_adjacent() {
        let rs = vec![MergeableRegion::new(0, 10), MergeableRegion::new(10, 20)];
        let merged = merge_regions(rs);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].end, 20);
    }

    #[test]
    fn merge_regions_empty() {
        let merged = merge_regions(vec![]);
        assert!(merged.is_empty());
    }
}
