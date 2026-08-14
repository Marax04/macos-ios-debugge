//! Compiler-specific heuristics for function detection.
//!
//! Each [`CompilerHeuristic`] implementation provides additional signals that
//! complement the generic prologue-pattern scanner.  The heuristics are applied
//! *after* the primary strategy pass and produce additional [`FunctionBoundary`]
//! candidates at [`Confidence::Medium`] or lower.
//!
//! Implemented heuristics:
//!
//! | # | Heuristic | Compiler | Notes |
//! |---|-----------|----------|-------|
//! | 1 | Function alignment gaps | MSVC | PE functions are aligned to 16 bytes; look for code after NOP/INT3 padding |
//! | 2 | GCC cold section detection | GCC | `.text.unlikely` / `__attribute__((cold))` creates a separate cluster of function starts |
//! | 3 | Clang profile-guided reordering | Clang PGO | Functions moved by PGO to `.text.hot`; detect by cluster of function-start addresses with high call density |
//! | 4 | MSVC SEH prologue | MSVC | `__security_cookie` + `__C_specific_handler` preamble pattern |
//! | 5 | GCC stack canary prologue | GCC | `mov __stack_chk_guard@GOT` pattern |
//! | 6 | Clang sanitizer entry | ASAN/TSAN | `__asan_function_enter` call immediately after prologue |
//! | 7 | MSVC CFGuard dispatch | MSVC CFG | `jmp [__guard_dispatch_icall_fptr]` thunk at function entry |
//! | 8 | Epilogue-based gap detection | all | Scan for RET / RET imm16 followed by padding → new function start |
//! | 9 | Symbol prefix heuristic | all | Names matching `_Z`, `?`, `sub_`, `j_`, etc. are strong signals |

use crate::{Confidence, DetectionSource, FunctionBoundary, MemorySlice};
use rustre_core::address::Address;

// ─────────────────────────────────────────────────────────────────────────────
// CompilerKind
// ─────────────────────────────────────────────────────────────────────────────

/// The compiler family a heuristic targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CompilerKind {
    Msvc,
    Gcc,
    Clang,
    /// Heuristic applies to multiple compilers.
    Generic,
}

impl CompilerKind {
    /// Short tag.
    #[must_use]
    pub const fn tag(self) -> &'static str {
        match self {
            Self::Msvc => "msvc",
            Self::Gcc => "gcc",
            Self::Clang => "clang",
            Self::Generic => "generic",
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// HeuristicResult
// ─────────────────────────────────────────────────────────────────────────────

/// Candidate function start produced by a heuristic.
#[derive(Debug, Clone)]
pub struct HeuristicResult {
    /// Candidate start address.
    pub address: Address,
    /// Confidence of the heuristic's signal.
    pub confidence: Confidence,
    /// Human-readable reason.
    pub reason: String,
    /// The compiler heuristic that produced this result.
    pub compiler: CompilerKind,
}

impl HeuristicResult {
    /// Convert to a [`FunctionBoundary`].
    #[must_use]
    pub const fn to_boundary(&self) -> FunctionBoundary {
        FunctionBoundary::new(self.address, self.confidence, DetectionSource::HeuristicGap)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CompilerHeuristic trait
// ─────────────────────────────────────────────────────────────────────────────

/// A single compiler-specific heuristic.
pub trait CompilerHeuristic: Send + Sync {
    /// Which compiler this heuristic targets.
    fn compiler(&self) -> CompilerKind;
    /// Short descriptive name.
    fn name(&self) -> &str;
    /// Run the heuristic over `mem`, returning additional candidates.
    fn run(&self, mem: &MemorySlice<'_>) -> Vec<HeuristicResult>;
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. MSVC function-alignment heuristic
// ─────────────────────────────────────────────────────────────────────────────

/// MSVC aligns functions to 16-byte boundaries and fills the gap with `0xCC`
/// (INT3) or `0x90` (NOP).
///
/// A non-INT3, non-NOP byte at a 16-byte boundary
/// that follows INT3 padding is a strong candidate for a function start.
pub struct MsvcAlignmentHeuristic {
    pub alignment: usize,
}

impl Default for MsvcAlignmentHeuristic {
    fn default() -> Self {
        Self { alignment: 16 }
    }
}

impl CompilerHeuristic for MsvcAlignmentHeuristic {
    fn compiler(&self) -> CompilerKind {
        CompilerKind::Msvc
    }

    fn name(&self) -> &'static str {
        "msvc_function_alignment"
    }

    fn run(&self, mem: &MemorySlice<'_>) -> Vec<HeuristicResult> {
        let mut results = Vec::new();
        let bytes = mem.bytes;
        let base = mem.base.as_u64();
        let align = self.alignment;

        if bytes.len() < align {
            return results;
        }

        let mut i = 0usize;
        while i + align <= bytes.len() {
            // Check that the `align` bytes leading up to `i` are all INT3/NOP.
            let pad_start = i.saturating_sub(align);
            let all_pad = bytes[pad_start..i].iter().all(|&b| b == 0xCC || b == 0x90);

            if i > 0 && all_pad && bytes[i] != 0xCC && bytes[i] != 0x90 {
                // This byte is at an alignment boundary, preceded by padding.
                let addr = Address::new(base + i as u64);
                results.push(HeuristicResult {
                    address: addr,
                    confidence: Confidence::Medium,
                    reason: format!(
                        "MSVC: 0x{:X} follows {}-byte INT3/NOP padding at {}-byte boundary",
                        bytes[i], align, align
                    ),
                    compiler: CompilerKind::Msvc,
                });
            }
            i += align;
        }

        results
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. GCC cold-section detection
// ─────────────────────────────────────────────────────────────────────────────

/// GCC emits `__attribute__((cold))` functions and rarely-executed handlers in
/// a `.text.unlikely` section.
///
/// They often appear as isolated clusters with
/// a valid prologue byte preceded by a large region of zeros or INT3 padding.
///
/// This heuristic scans for a run of `min_gap` zero/INT3 bytes followed by a
/// valid function-start byte (E.g. `0x55` or `0x48`).
pub struct GccColdSectionHeuristic {
    pub min_gap: usize,
    /// Bytes that count as "cold gap" filler.
    pub gap_bytes: Vec<u8>,
    /// First bytes that plausibly start a function.
    pub start_bytes: Vec<u8>,
}

impl Default for GccColdSectionHeuristic {
    fn default() -> Self {
        Self {
            min_gap: 32,
            gap_bytes: vec![0x00, 0xCC, 0x90],
            start_bytes: vec![0x55, 0x48, 0x41, 0xF3],
        }
    }
}

impl CompilerHeuristic for GccColdSectionHeuristic {
    fn compiler(&self) -> CompilerKind {
        CompilerKind::Gcc
    }

    fn name(&self) -> &'static str {
        "gcc_cold_section"
    }

    fn run(&self, mem: &MemorySlice<'_>) -> Vec<HeuristicResult> {
        let mut results = Vec::new();
        let bytes = mem.bytes;
        let base = mem.base.as_u64();

        let mut gap_run = 0usize;
        let gap_set: std::collections::HashSet<u8> = self.gap_bytes.iter().copied().collect();

        for (i, &b) in bytes.iter().enumerate() {
            if gap_set.contains(&b) {
                gap_run += 1;
            } else {
                if gap_run >= self.min_gap && self.start_bytes.contains(&b) {
                    let addr = Address::new(base + i as u64);
                    results.push(HeuristicResult {
                        address: addr,
                        confidence: Confidence::Low,
                        reason: format!(
                            "GCC cold section: {}-byte gap at 0x{:X} followed by start byte 0x{:02X}",
                            gap_run, addr.as_u64(), b
                        ),
                        compiler: CompilerKind::Gcc,
                    });
                }
                gap_run = 0;
            }
        }
        results
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. Clang PGO hot-section detection
// ─────────────────────────────────────────────────────────────────────────────

/// Clang's profile-guided reordering groups hot functions consecutively.
///
/// This heuristic detects a cluster of function starts (from the primary pass)
/// that are densely packed within a configurable window, elevating their
/// confidence slightly.
///
/// It operates on already-found candidates rather than raw bytes; the caller
/// is expected to pass the existing candidate list and this heuristic returns
/// promoted entries.
pub struct ClangPgoHeuristic {
    /// If this many candidates appear within `window_bytes` of each other,
    /// consider the region PGO-ordered and promote confidence.
    pub cluster_threshold: usize,
    pub window_bytes: u64,
}

impl Default for ClangPgoHeuristic {
    fn default() -> Self {
        Self {
            cluster_threshold: 5,
            window_bytes: 4096,
        }
    }
}

impl ClangPgoHeuristic {
    /// Given a sorted list of candidate addresses, return those that fall in a
    /// dense cluster (implying PGO ordering) with promoted confidence.
    #[must_use]
    pub fn promote_cluster(&self, candidates: &[Address]) -> Vec<HeuristicResult> {
        let mut results = Vec::new();
        let n = candidates.len();

        // Manual cursor so a cluster can be SKIPPED PAST, as the comment at the
        // bottom of the loop always claimed. It used to be a `break`, which
        // left the whole scan after the first dense cluster and silently
        // dropped every later one — on a PGO-ordered binary that is most of
        // the hot text.
        let mut i = 0usize;
        while i < n {
            // Count how many candidates fall within `window_bytes` of candidates[i].
            let window_end = candidates[i].as_u64().saturating_add(self.window_bytes);
            let cluster_size = candidates[i..]
                .iter()
                .take_while(|&&a| a.as_u64() < window_end)
                .count();

            if cluster_size >= self.cluster_threshold {
                for &addr in &candidates[i..i + cluster_size.min(n - i)] {
                    results.push(HeuristicResult {
                        address: addr,
                        confidence: Confidence::Medium,
                        reason: format!(
                            "Clang PGO cluster: {} functions within {} bytes",
                            cluster_size, self.window_bytes
                        ),
                        compiler: CompilerKind::Clang,
                    });
                }
                // Skip past the cluster — each member is promoted once.
                i += cluster_size;
            } else {
                i += 1;
            }
        }
        results
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. MSVC SEH / security-cookie prologue
// ─────────────────────────────────────────────────────────────────────────────

/// MSVC functions with /GS (stack security cookie) begin with a specific
/// `mov rax, __security_cookie` or `xor` pattern that is recognizable.
///
/// x86-64 pattern: `48 8B 05 xx xx xx xx` (mov rax,[rip+offset]) for loading
/// the security cookie, preceded by a normal prologue.
pub struct MsvcSecurityCookieHeuristic;

impl CompilerHeuristic for MsvcSecurityCookieHeuristic {
    fn compiler(&self) -> CompilerKind {
        CompilerKind::Msvc
    }

    fn name(&self) -> &'static str {
        "msvc_security_cookie"
    }

    fn run(&self, mem: &MemorySlice<'_>) -> Vec<HeuristicResult> {
        let mut results = Vec::new();
        let bytes = mem.bytes;
        let base = mem.base.as_u64();

        // Look for: push rbp (55) / sub rsp imm (48 83 EC) followed by
        // mov rax,[rip+disp] (48 8B 05) within the first ~32 bytes.
        let mut i = 0usize;
        while i + 10 <= bytes.len() {
            // Detect: 55 48 89 E5 ... 48 8B 05
            if bytes[i] == 0x55 {
                // Look ahead for the security cookie load within 16 bytes.
                for j in 1..16usize.min(bytes.len() - i) {
                    if i + j + 6 <= bytes.len()
                        && bytes[i + j] == 0x48
                        && bytes[i + j + 1] == 0x8B
                        && bytes[i + j + 2] == 0x05
                    {
                        let addr = Address::new(base + i as u64);
                        results.push(HeuristicResult {
                            address: addr,
                            confidence: Confidence::High,
                            reason: format!(
                                "MSVC /GS: push rbp + mov rax,[rip+disp] (security cookie load) at 0x{:X}",
                                addr.as_u64()
                            ),
                            compiler: CompilerKind::Msvc,
                        });
                        break;
                    }
                }
            }
            i += 1;
        }
        results
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 5. GCC stack canary
// ─────────────────────────────────────────────────────────────────────────────

/// GCC's `-fstack-protector` inserts a load from `__stack_chk_guard@GOT`
/// near the start of protected functions.
///
/// The pattern (x86-64, PIE) is:
/// `48 8B 05 xx xx xx xx` (same as MSVC cookie but different symbol).
/// We use GOT-relative address clustering to distinguish.
///
/// This heuristic simply flags any function that has a RIP-relative MOV in
/// the first 32 bytes, treating it as a potential canary loader.
pub struct GccStackCanaryHeuristic;

impl CompilerHeuristic for GccStackCanaryHeuristic {
    fn compiler(&self) -> CompilerKind {
        CompilerKind::Gcc
    }

    fn name(&self) -> &'static str {
        "gcc_stack_canary"
    }

    fn run(&self, mem: &MemorySlice<'_>) -> Vec<HeuristicResult> {
        let mut results = Vec::new();
        let bytes = mem.bytes;
        let base = mem.base.as_u64();

        let mut i = 0usize;
        while i + 7 <= bytes.len() {
            // 64 48 8B 04 25: mov rax, fs:[N] — GCC TLS canary on Linux x86-64.
            if bytes[i] == 0x64
                && i + 4 < bytes.len()
                && bytes[i + 1] == 0x48
                && bytes[i + 2] == 0x8B
                && bytes[i + 3] == 0x04
                && bytes[i + 4] == 0x25
            {
                // Walk backwards up to 32 bytes to find the function entry —
                // actually SCANNING for a prologue, rather than subtracting a
                // fixed 32. The blind subtraction was wrong by
                // (32 − real prologue distance) and normally landed in the
                // middle of the PREVIOUS function. `MsvcSecurityCookieHeuristic`
                // gets this right by anchoring on the prologue byte; this is
                // the mirror of that, scanning back instead of ahead.
                let is_prologue = |o: usize| {
                    bytes[o] == 0x55 // push rbp
                        || (o + 2 < bytes.len()
                            && bytes[o] == 0x48
                            && bytes[o + 1] == 0x83
                            && bytes[o + 2] == 0xEC) // sub rsp, imm8
                };
                // The NEAREST preceding prologue is the entry of the function
                // that contains this canary load.
                let entry = (1..=i.min(32)).find(|&d| is_prologue(i - d)).map(|d| i - d);

                if let Some(candidate_offset) = entry {
                    let addr = Address::new(base + candidate_offset as u64);
                    results.push(HeuristicResult {
                        address: addr,
                        confidence: Confidence::Low,
                        reason: format!(
                            "GCC stack canary (mov rax,fs:[N]) at 0x{:X}",
                            base + i as u64
                        ),
                        compiler: CompilerKind::Gcc,
                    });
                }
                // If no prologue is in range we emit NOTHING: a fabricated
                // address pointing into another function is worse for every
                // consumer than one fewer low-confidence candidate.
                i += 5;
                continue;
            }
            i += 1;
        }
        results
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 6. Clang sanitizer entry
// ─────────────────────────────────────────────────────────────────────────────

/// ASAN/TSAN-instrumented functions call `__asan_function_enter` or
/// `__tsan_func_entry` near the top of the function.
///
/// We detect this via the
/// CALL instruction (E8 xx xx xx xx) within the first 32 bytes of a prologue.
///
/// Since these calls appear right after the frame setup, any block with a CALL
/// in byte positions 4–32 is a candidate.
pub struct ClangSanitizerHeuristic;

impl CompilerHeuristic for ClangSanitizerHeuristic {
    fn compiler(&self) -> CompilerKind {
        CompilerKind::Clang
    }

    fn name(&self) -> &'static str {
        "clang_sanitizer_entry"
    }

    fn run(&self, mem: &MemorySlice<'_>) -> Vec<HeuristicResult> {
        let mut results = Vec::new();
        let bytes = mem.bytes;
        let base = mem.base.as_u64();

        // Pattern: prologue byte (55 or 48 8x) followed within 32 bytes by a
        // CALL rel32 (E8).
        let mut i = 0usize;
        while i + 5 <= bytes.len() {
            if bytes[i] == 0x55 || (bytes[i] == 0x48 && i + 1 < bytes.len()) {
                // Look for E8 within 32 bytes.
                for j in 1..32usize.min(bytes.len() - i) {
                    if bytes[i + j] == 0xE8 && i + j + 5 <= bytes.len() {
                        let addr = Address::new(base + i as u64);
                        results.push(HeuristicResult {
                            address: addr,
                            confidence: Confidence::Low,
                            reason: format!(
                                "Clang sanitizer: CALL at +{} bytes from prologue at 0x{:X}",
                                j,
                                addr.as_u64()
                            ),
                            compiler: CompilerKind::Clang,
                        });
                        break;
                    }
                }
            }
            i += 1;
        }
        results
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 7. MSVC CFGuard dispatch thunk
// ─────────────────────────────────────────────────────────────────────────────

/// MSVC Control Flow Guard inserts a `jmp [__guard_dispatch_icall_fptr]` stub
/// at indirect-call sites.  The pattern is `FF 25 xx xx xx xx` (JMP [rip+disp])
/// at the very start of a block.
pub struct MsvcCfGuardHeuristic;

impl CompilerHeuristic for MsvcCfGuardHeuristic {
    fn compiler(&self) -> CompilerKind {
        CompilerKind::Msvc
    }

    fn name(&self) -> &'static str {
        "msvc_cfguard_dispatch"
    }

    fn run(&self, mem: &MemorySlice<'_>) -> Vec<HeuristicResult> {
        let mut results = Vec::new();
        let bytes = mem.bytes;
        let base = mem.base.as_u64();

        let mut i = 0usize;
        while i + 6 <= bytes.len() {
            // JMP [rip+disp32]: FF 25 xx xx xx xx
            if bytes[i] == 0xFF && i + 1 < bytes.len() && bytes[i + 1] == 0x25 {
                let addr = Address::new(base + i as u64);
                results.push(HeuristicResult {
                    address: addr,
                    confidence: Confidence::Medium,
                    reason: format!(
                        "MSVC CFGuard: JMP [rip+disp32] thunk at 0x{:X}",
                        addr.as_u64()
                    ),
                    compiler: CompilerKind::Msvc,
                });
                i += 6;
                continue;
            }
            i += 1;
        }
        results
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 8. Epilogue-based gap detection
// ─────────────────────────────────────────────────────────────────────────────

/// Scan for RET / RET imm16 instructions followed by alignment padding.
/// The first non-padding byte after the epilogue is a potential function start.
pub struct EpilogueGapHeuristic {
    pub padding_bytes: Vec<u8>,
    pub min_gap: usize,
}

impl Default for EpilogueGapHeuristic {
    fn default() -> Self {
        Self {
            padding_bytes: vec![0xCC, 0x90, 0x00],
            min_gap: 1,
        }
    }
}

impl CompilerHeuristic for EpilogueGapHeuristic {
    fn compiler(&self) -> CompilerKind {
        CompilerKind::Generic
    }

    fn name(&self) -> &'static str {
        "epilogue_gap"
    }

    fn run(&self, mem: &MemorySlice<'_>) -> Vec<HeuristicResult> {
        let mut results = Vec::new();
        let bytes = mem.bytes;
        let base = mem.base.as_u64();
        let pad_set: std::collections::HashSet<u8> = self.padding_bytes.iter().copied().collect();

        let mut i = 0usize;
        while i < bytes.len() {
            // Detect RET (C3), RETN (C3), RET imm16 (C2 xx xx), RETF imm16 (CA xx xx).
            let is_ret = bytes[i] == 0xC3
                || bytes[i] == 0xCB
                || (bytes[i] == 0xC2 && i + 2 < bytes.len())
                || (bytes[i] == 0xCA && i + 2 < bytes.len());

            if is_ret {
                // Skip the RET instruction.
                let ret_end = if bytes[i] == 0xC2 || bytes[i] == 0xCA {
                    i + 3
                } else {
                    i + 1
                };

                // Count padding bytes.
                let mut j = ret_end;
                while j < bytes.len() && pad_set.contains(&bytes[j]) {
                    j += 1;
                }

                let gap = j - ret_end;
                if gap >= self.min_gap && j < bytes.len() {
                    let addr = Address::new(base + j as u64);
                    results.push(HeuristicResult {
                        address: addr,
                        confidence: Confidence::Low,
                        reason: format!(
                            "Epilogue gap: {} padding bytes after RET → function start at 0x{:X}",
                            gap,
                            addr.as_u64()
                        ),
                        compiler: CompilerKind::Generic,
                    });
                }
                i = j;
                continue;
            }
            i += 1;
        }
        results
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 9. Symbol-name prefix heuristic
// ─────────────────────────────────────────────────────────────────────────────

/// Symbol names matching certain prefixes are high-confidence function entries:
/// - `_Z` — GCC/Clang C++ mangled
/// - `?` — MSVC C++ mangled
/// - `sub_` — IDA-style auto-generated function name
/// - `j_` — IDA thunk placeholder
/// - `_` + digit — C library internal
/// - `__` — compiler-generated / GCC internal
pub struct SymbolPrefixHeuristic {
    pub prefixes: Vec<String>,
}

impl Default for SymbolPrefixHeuristic {
    fn default() -> Self {
        Self {
            prefixes: vec![
                "_Z".into(),
                "?".into(),
                "sub_".into(),
                "j_".into(),
                "__".into(),
            ],
        }
    }
}

impl SymbolPrefixHeuristic {
    /// Classify a symbol name.  Returns the confidence level if the name
    /// matches a known function prefix, or `None` otherwise.
    #[must_use]
    pub fn classify(&self, name: &str) -> Option<Confidence> {
        for prefix in &self.prefixes {
            if name.starts_with(prefix.as_str()) {
                return Some(Confidence::High);
            }
        }
        None
    }

    /// Given a list of `(name, address)` pairs, return candidates where the
    /// name prefix implies a function entry.
    #[must_use]
    pub fn run_on_symbols(&self, symbols: &[(&str, Address)]) -> Vec<HeuristicResult> {
        let mut results = Vec::new();
        for &(name, addr) in symbols {
            if let Some(conf) = self.classify(name) {
                results.push(HeuristicResult {
                    address: addr,
                    confidence: conf,
                    reason: format!("Symbol prefix match: '{name}'"),
                    compiler: CompilerKind::Generic,
                });
            }
        }
        results
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// HeuristicEngine — run all heuristics and merge results
// ─────────────────────────────────────────────────────────────────────────────

/// Runs a configurable set of heuristics over a memory slice and merges the
/// candidate results with an existing list of known function boundaries.
pub struct HeuristicEngine {
    pub heuristics: Vec<Box<dyn CompilerHeuristic>>,
}

impl Default for HeuristicEngine {
    fn default() -> Self {
        Self {
            heuristics: vec![
                Box::new(MsvcAlignmentHeuristic::default()),
                Box::new(GccColdSectionHeuristic::default()),
                Box::new(MsvcSecurityCookieHeuristic),
                Box::new(GccStackCanaryHeuristic),
                Box::new(ClangSanitizerHeuristic),
                Box::new(MsvcCfGuardHeuristic),
                Box::new(EpilogueGapHeuristic::default()),
            ],
        }
    }
}

impl HeuristicEngine {
    /// Create an engine with no heuristics.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            heuristics: Vec::new(),
        }
    }

    /// Add a heuristic to the engine.
    pub fn add<H: CompilerHeuristic + 'static>(&mut self, h: H) {
        self.heuristics.push(Box::new(h));
    }

    /// Run all heuristics over `mem` and return a deduplicated list of
    /// [`FunctionBoundary`] candidates.
    ///
    /// Candidates are merged with `existing` by taking the highest confidence
    /// for each unique address.
    #[must_use]
    pub fn run(
        &self,
        mem: &MemorySlice<'_>,
        existing: &[FunctionBoundary],
    ) -> Vec<FunctionBoundary> {
        use std::collections::HashMap;

        // Seed with existing boundaries.
        let mut by_addr: HashMap<u64, FunctionBoundary> = existing
            .iter()
            .map(|fb| (fb.start.as_u64(), fb.clone()))
            .collect();

        for h in &self.heuristics {
            for result in h.run(mem) {
                let key = result.address.as_u64();
                let new_fb = result.to_boundary();
                let entry = by_addr.entry(key).or_insert_with(|| new_fb.clone());
                // Promote to higher confidence if found by heuristic.
                if new_fb.confidence > entry.confidence {
                    *entry = new_fb;
                }
            }
        }

        let mut output: Vec<FunctionBoundary> = by_addr.into_values().collect();
        output.sort_by_key(|fb| fb.start.as_u64());
        output
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn a(n: u64) -> Address {
        Address::new(n)
    }

    fn _mem(base: u64, bytes: Vec<u8>) -> (Vec<u8>, Address) {
        (bytes, Address::new(base))
    }

    fn make_slice(base: Address, data: &[u8]) -> MemorySlice<'_> {
        MemorySlice::new(base, data)
    }

    // ── CompilerKind ──────────────────────────────────────────────────────

    #[test]
    fn compiler_kind_tags_unique() {
        let kinds = [
            CompilerKind::Msvc,
            CompilerKind::Gcc,
            CompilerKind::Clang,
            CompilerKind::Generic,
        ];
        let tags: std::collections::HashSet<&str> = kinds.iter().map(|k| k.tag()).collect();
        assert_eq!(tags.len(), kinds.len());
    }

    // ── MsvcAlignmentHeuristic ────────────────────────────────────────────

    #[test]
    fn msvc_alignment_detects_after_int3_padding() {
        // 16 bytes: 15×0xCC (INT3) + 1×0x55 (push rbp)
        let mut data = vec![0xCCu8; 16];
        data[15] = 0x55;
        let slice = make_slice(a(0x1000), &data);
        let h = MsvcAlignmentHeuristic::default();
        let _results = h.run(&slice);
        // We might get a hit at 0x1010 (second 16-byte boundary) if there's enough data.
        // The hit at offset 16 requires at least 32 bytes.
        // With only 16 bytes, offset 16 == len, so no result expected at this boundary.
        // Add more data to test properly:
        let mut data2 = vec![0xCCu8; 32];
        data2[16] = 0x55;
        let slice2 = make_slice(a(0x1000), &data2);
        let results2 = h.run(&slice2);
        assert!(results2.iter().any(|r| r.address == a(0x1010)));
    }

    #[test]
    fn msvc_alignment_no_result_when_no_padding() {
        let data: Vec<u8> = (0..32).map(|i| i as u8).collect();
        let slice = make_slice(a(0x1000), &data);
        let h = MsvcAlignmentHeuristic::default();
        let results = h.run(&slice);
        assert!(results.is_empty());
    }

    // ── GccColdSectionHeuristic ───────────────────────────────────────────

    #[test]
    fn gcc_cold_detects_after_large_gap() {
        let mut data = vec![0x00u8; 64];
        data[63] = 0x55; // push rbp after 63-byte zero gap
        let slice = make_slice(a(0x2000), &data);
        let h = GccColdSectionHeuristic::default();
        let results = h.run(&slice);
        assert!(!results.is_empty());
        assert!(results.iter().any(|r| r.address == a(0x203F)));
    }

    #[test]
    fn gcc_cold_no_result_below_min_gap() {
        let mut data = vec![0x00u8; 10]; // only 10 zeros
        data[9] = 0x55;
        let slice = make_slice(a(0x2000), &data);
        let h = GccColdSectionHeuristic::default();
        let results = h.run(&slice);
        assert!(results.is_empty());
    }

    // ── MsvcSecurityCookieHeuristic ───────────────────────────────────────

    #[test]
    fn msvc_cookie_detects_pattern() {
        // push rbp (55), mov rbp,rsp (48 89 E5), ..., mov rax,[rip+disp] (48 8B 05 xx xx xx xx)
        let mut data = vec![0x90u8; 20];
        data[0] = 0x55;
        data[5] = 0x48;
        data[6] = 0x8B;
        data[7] = 0x05;
        data[8] = 0x00;
        data[9] = 0x00;
        data[10] = 0x00;
        data[11] = 0x00;
        let slice = make_slice(a(0x3000), &data);
        let h = MsvcSecurityCookieHeuristic;
        let results = h.run(&slice);
        assert!(!results.is_empty());
        assert!(results.iter().any(|r| r.address == a(0x3000)));
    }

    // ── GccStackCanaryHeuristic ───────────────────────────────────────────

    #[test]
    fn gcc_canary_detects_fs_pattern() {
        let mut data = vec![0x90u8; 40];
        // A canary load only identifies a function ENTRY if there is a
        // prologue to anchor it to, so the fixture now contains one. (Before,
        // the heuristic reported `offset - 32` unconditionally, which is why
        // a prologue-less blob still produced a — meaningless — result.)
        data[4] = 0x55; // push rbp
        // Inject: 64 48 8B 04 25 at offset 10
        data[10] = 0x64;
        data[11] = 0x48;
        data[12] = 0x8B;
        data[13] = 0x04;
        data[14] = 0x25;
        let slice = make_slice(a(0x4000), &data);
        let h = GccStackCanaryHeuristic;
        let results = h.run(&slice);
        assert!(!results.is_empty());
        assert_eq!(results[0].address.as_u64(), 0x4004, "the `push rbp`");
    }

    // ── ClangSanitizerHeuristic ───────────────────────────────────────────

    #[test]
    fn clang_sanitizer_detects_call_after_prologue() {
        let mut data = vec![0x90u8; 40];
        data[0] = 0x55; // push rbp
        // CALL rel32 at offset 10
        data[10] = 0xE8;
        data[11] = 0x00;
        data[12] = 0x00;
        data[13] = 0x00;
        data[14] = 0x00;
        let slice = make_slice(a(0x5000), &data);
        let h = ClangSanitizerHeuristic;
        let results = h.run(&slice);
        assert!(!results.is_empty());
        assert!(results.iter().any(|r| r.address == a(0x5000)));
    }

    // ── MsvcCfGuardHeuristic ──────────────────────────────────────────────

    #[test]
    fn msvc_cfguard_detects_jmp_indirect() {
        let mut data = vec![0x90u8; 16];
        // FF 25 xx xx xx xx
        data[0] = 0xFF;
        data[1] = 0x25;
        data[2] = 0x00;
        data[3] = 0x00;
        data[4] = 0x00;
        data[5] = 0x00;
        let slice = make_slice(a(0x6000), &data);
        let h = MsvcCfGuardHeuristic;
        let results = h.run(&slice);
        assert!(!results.is_empty());
        assert_eq!(results[0].address, a(0x6000));
    }

    // ── EpilogueGapHeuristic ──────────────────────────────────────────────

    #[test]
    fn epilogue_gap_detects_after_ret_int3() {
        let mut data = vec![0xCCu8; 20];
        data[0] = 0x90; // nop (so we don't start with padding)
        data[1] = 0xC3; // ret
        data[2] = 0xCC; // int3
        data[3] = 0xCC; // int3
        data[4] = 0x55; // push rbp — new function
        let slice = make_slice(a(0x7000), &data);
        let h = EpilogueGapHeuristic::default();
        let results = h.run(&slice);
        assert!(!results.is_empty());
        assert!(results.iter().any(|r| r.address == a(0x7004)));
    }

    #[test]
    fn epilogue_gap_ret_imm16() {
        let mut data = vec![0x90u8; 10];
        data[0] = 0xC2; // RET imm16
        data[1] = 0x04;
        data[2] = 0x00;
        data[3] = 0xCC; // padding
        data[4] = 0x55; // new function
        let slice = make_slice(a(0x8000), &data);
        let h = EpilogueGapHeuristic::default();
        let results = h.run(&slice);
        assert!(!results.is_empty());
        assert!(results.iter().any(|r| r.address == a(0x8004)));
    }

    // ── SymbolPrefixHeuristic ─────────────────────────────────────────────

    #[test]
    fn symbol_prefix_cxx_mangled_gcc() {
        let h = SymbolPrefixHeuristic::default();
        assert_eq!(h.classify("_ZN3foo3barEv"), Some(Confidence::High));
    }

    #[test]
    fn symbol_prefix_msvc_mangled() {
        let h = SymbolPrefixHeuristic::default();
        assert_eq!(h.classify("?foo@@YAXXZ"), Some(Confidence::High));
    }

    #[test]
    fn symbol_prefix_ida_sub() {
        let h = SymbolPrefixHeuristic::default();
        assert_eq!(h.classify("sub_401000"), Some(Confidence::High));
    }

    #[test]
    fn symbol_prefix_no_match() {
        let h = SymbolPrefixHeuristic::default();
        assert!(h.classify("main").is_none());
    }

    #[test]
    fn symbol_prefix_run_on_symbols() {
        let h = SymbolPrefixHeuristic::default();
        let syms = vec![
            ("_ZN3fooEv", a(0x1000)),
            ("main", a(0x2000)),
            ("sub_401000", a(0x3000)),
        ];
        let results = h.run_on_symbols(&syms);
        assert_eq!(results.len(), 2);
        assert!(results.iter().any(|r| r.address == a(0x1000)));
        assert!(results.iter().any(|r| r.address == a(0x3000)));
    }

    // ── HeuristicEngine ───────────────────────────────────────────────────

    #[test]
    fn engine_empty_returns_existing_only() {
        let engine = HeuristicEngine::empty();
        let data = vec![0x90u8; 32];
        let slice = make_slice(a(0x1000), &data);
        let existing = vec![FunctionBoundary::new(
            a(0x1000),
            Confidence::High,
            DetectionSource::SymbolTable,
        )];
        let result = engine.run(&slice, &existing);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].start, a(0x1000));
    }

    #[test]
    fn engine_merges_and_sorts() {
        let mut engine = HeuristicEngine::empty();
        engine.add(EpilogueGapHeuristic::default());

        let mut data = vec![0xCCu8; 20];
        data[0] = 0x90;
        data[1] = 0xC3; // ret
        data[2] = 0xCC;
        data[3] = 0x55; // new fn start
        let slice = make_slice(a(0xA000), &data);
        let existing = vec![FunctionBoundary::new(
            a(0xA000),
            Confidence::Medium,
            DetectionSource::ProloguePattern,
        )];
        let result = engine.run(&slice, &existing);
        // Should have both 0xA000 (existing) and 0xA003 (gap).
        assert!(result.iter().any(|fb| fb.start == a(0xA000)));
        assert!(result.iter().any(|fb| fb.start == a(0xA003)));
        // Results are sorted.
        for w in result.windows(2) {
            assert!(w[0].start.as_u64() <= w[1].start.as_u64());
        }
    }

    #[test]
    fn engine_promotes_confidence() {
        let mut engine = HeuristicEngine::empty();
        engine.add(MsvcCfGuardHeuristic);

        let mut data = vec![0x90u8; 16];
        data[0] = 0xFF;
        data[1] = 0x25;
        data[2] = 0x00;
        data[3] = 0x00;
        data[4] = 0x00;
        data[5] = 0x00;
        let slice = make_slice(a(0xB000), &data);
        // Start with Low confidence for the address.
        let existing = vec![FunctionBoundary::new(
            a(0xB000),
            Confidence::Low,
            DetectionSource::HeuristicGap,
        )];
        let result = engine.run(&slice, &existing);
        let fb = result.iter().find(|f| f.start == a(0xB000)).unwrap();
        // CFGuard heuristic gives Medium; should be promoted from Low.
        assert!(fb.confidence >= Confidence::Medium);
    }

    // ── HeuristicResult ───────────────────────────────────────────────────

    #[test]
    fn heuristic_result_to_boundary() {
        let r = HeuristicResult {
            address: a(0x1234),
            confidence: Confidence::High,
            reason: "test".into(),
            compiler: CompilerKind::Generic,
        };
        let fb = r.to_boundary();
        assert_eq!(fb.start, a(0x1234));
        assert_eq!(fb.confidence, Confidence::High);
    }

    // ── ClangPgoHeuristic ─────────────────────────────────────────────────

    #[test]
    fn clang_pgo_cluster_promotes_dense_region() {
        let h = ClangPgoHeuristic::default();
        // 6 candidates within 4096 bytes.
        let candidates: Vec<Address> = (0..6u64).map(|i| a(0x1000 + i * 100)).collect();
        let results = h.promote_cluster(&candidates);
        assert!(!results.is_empty());
        assert!(results.iter().all(|r| r.confidence == Confidence::Medium));
    }

    #[test]
    fn clang_pgo_no_promotion_for_sparse_region() {
        let h = ClangPgoHeuristic::default();
        // 4 candidates spread over 10KB (below threshold of 5).
        let candidates: Vec<Address> = (0..4u64).map(|i| a(0x1000 + i * 3000)).collect();
        let results = h.promote_cluster(&candidates);
        assert!(results.is_empty());
    }
}
