//! `noreturn` function detector.
//!
//! Identifies functions that never return to their caller by looking for:
//! 1. Known-noreturn CRT / OS patterns (`abort`, `exit`, `_exit`, `longjmp`,
//!    `__stack_chk_fail`, `raise` with SIGABRT, etc.).
//! 2. Functions whose every code path ends in an unconditional non-call transfer
//!    (tail-jump out of the module, `UD2`, `HLT`).
//! 3. Functions that call **only** noreturn callees and then execute an
//!    unconditional jump or fall off the end — i.e. `noreturn` propagation up
//!    the call graph.
//!
//! The result is a set of function addresses labelled as noreturn together with
//! evidence describing why.

use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;
use rustre_core::address::Address;
use serde::{Deserialize, Serialize};

use crate::FunctionBoundary;

// ── Public coarse-grained API (FunctionBoundary + xrefs) ─────────────────────

/// A single classification produced by [`detect_noreturn_functions`].
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct NoReturnHit {
    /// Address of the function classified as noreturn.
    pub addr: u64,
    /// Short tag identifying which heuristic fired.
    pub reason: String,
}

/// Detect functions that never return using four cheap heuristics.
///
/// `xrefs` is a list of `(call_site_addr, callee_addr)` pairs. The call-site
/// address is used to attribute an edge to its containing function via the
/// `[start, end)` range of each [`FunctionBoundary`].
///
/// Heuristics (any one triggers, in order):
/// 1. Last outgoing call edge targets a function whose name is a known
///    noreturn symbol (`abort`, `exit`, `__cxa_throw`, Rust panic helpers, …).
///    Reason: `"calls_abort"`.
/// 2. Function name itself matches a `ud2`/trap marker. Reason: `"ud2"`.
/// 3. The function has a self-edge — a call/jump targeting its own start —
///    and no other outgoing edges. Reason: `"infinite_loop"`.
/// 4. The function has zero outgoing edges and is not a known leaf returner
///    (no end address means we cannot bound it). Reason: `"no_ret"`.
#[must_use]
pub fn detect_noreturn_functions(
    funcs: &[FunctionBoundary],
    xrefs: &[(u64, u64)],
) -> Vec<NoReturnHit> {
    let mut by_start: HashMap<u64, &FunctionBoundary> = HashMap::with_capacity(funcs.len());
    for f in funcs {
        by_start.insert(f.start.as_u64(), f);
    }

    let mut sorted: Vec<&FunctionBoundary> = funcs.iter().collect();
    sorted.sort_by_key(|f| f.start.as_u64());

    let range_of = |f: &FunctionBoundary| -> (u64, u64) {
        let s = f.start.as_u64();
        let e = f
            .end
            .map(Address::as_u64)
            .or_else(|| {
                let idx = sorted
                    .binary_search_by_key(&s, |x| x.start.as_u64())
                    .ok()?;
                sorted.get(idx + 1).map(|n| n.start.as_u64())
            })
            .unwrap_or_else(|| s.saturating_add(1));
        (s, e.max(s.saturating_add(1)))
    };

    let mut out_edges: HashMap<u64, Vec<(u64, u64)>> = HashMap::new();
    for &(site, callee) in xrefs {
        let Ok(idx) = sorted.binary_search_by(|f| {
            let (s, e) = range_of(f);
            if site < s {
                std::cmp::Ordering::Greater
            } else if site >= e {
                std::cmp::Ordering::Less
            } else {
                std::cmp::Ordering::Equal
            }
        }) else { continue };
        let owner = sorted[idx].start.as_u64();
        out_edges.entry(owner).or_default().push((site, callee));
    }

    let mut hits = Vec::new();
    for f in &sorted {
        let addr = f.start.as_u64();
        let edges = out_edges.get(&addr).cloned().unwrap_or_default();

        // The last call *in the function body* is the one with the highest
        // site address — NOT `edges.last()`, which is merely the last edge in
        // xref input order and made this classification depend on how the
        // caller happened to order `xrefs`. Select by max site so the result
        // is deterministic and actually reflects the tail-call-to-noreturn
        // pattern this heuristic targets.
        if let Some(&(_, last_callee)) = edges.iter().max_by_key(|(site, _)| *site)
            && let Some(callee_fn) = by_start.get(&last_callee)
            && callee_fn.name.as_deref().is_some_and(is_known_noreturn_symbol)
        {
            hits.push(NoReturnHit { addr, reason: "calls_abort".into() });
            continue;
        }

        if f.name
            .as_deref()
            .is_some_and(|n| n.eq_ignore_ascii_case("ud2") || n.contains("__ud2") || n.contains(".trap"))
        {
            hits.push(NoReturnHit { addr, reason: "ud2".into() });
            continue;
        }

        let self_edges = edges.iter().filter(|(_, c)| *c == addr).count();
        if !edges.is_empty() && self_edges == edges.len() {
            hits.push(NoReturnHit { addr, reason: "infinite_loop".into() });
            continue;
        }

        if edges.is_empty() && f.end.is_none() {
            hits.push(NoReturnHit { addr, reason: "no_ret".into() });
        }
    }

    hits
}

// ── Errors ────────────────────────────────────────────────────────────────────

/// Errors produced by the noreturn detector.
#[derive(Debug)]
pub enum NoreturnError {
    /// A function address was queried that is not in the database.
    UnknownFunction(Address),
}

impl fmt::Display for NoreturnError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownFunction(a) => write!(f, "unknown function at {a:#x}"),
        }
    }
}

impl std::error::Error for NoreturnError {}

// ── EvidenceKind ──────────────────────────────────────────────────────────────

/// The reason a function was classified as noreturn.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EvidenceKind {
    /// The function name matches a well-known noreturn symbol.
    KnownSymbol,
    /// The function body ends with `UD2` / `INT 0x03` / `HLT`.
    TerminatingInstruction,
    /// Every path out of the function is through a noreturn callee.
    PropagatedFromCallees,
    /// The function ends with an unconditional jump outside the binary module.
    TailJumpOutOfModule,
    /// Manual / user annotation.
    UserAnnotated,
    /// The function raises SIGABRT (detects `raise(SIGABRT)` patterns).
    RaisesSigabrt,
    /// The function's last instruction is a tail-call (JMP or fall-through CALL
    /// with no following RET) targeting a known-noreturn callee.
    TailCallToNoreturn,
}

impl fmt::Display for EvidenceKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::KnownSymbol => write!(f, "KnownSymbol"),
            Self::TerminatingInstruction => write!(f, "TerminatingInstruction"),
            Self::PropagatedFromCallees => write!(f, "PropagatedFromCallees"),
            Self::TailJumpOutOfModule => write!(f, "TailJumpOutOfModule"),
            Self::UserAnnotated => write!(f, "UserAnnotated"),
            Self::RaisesSigabrt => write!(f, "RaisesSigabrt"),
            Self::TailCallToNoreturn => write!(f, "TailCallToNoreturn"),
        }
    }
}

// ── NoreturnEvidence ──────────────────────────────────────────────────────────

/// Evidence attached to a single noreturn classification.
#[derive(Debug, Clone)]
pub struct NoreturnEvidence {
    /// Why this function is considered noreturn.
    pub kind: EvidenceKind,
    /// Optional human-readable details.
    pub detail: Option<String>,
    /// Confidence score in `[0.0, 1.0]`.
    pub confidence: f32,
}

impl NoreturnEvidence {
    /// Construct evidence from a known symbol.
    #[must_use]
    pub fn known_symbol(symbol_name: impl Into<String>) -> Self {
        Self {
            kind: EvidenceKind::KnownSymbol,
            detail: Some(symbol_name.into()),
            confidence: 1.0,
        }
    }

    /// Evidence from a terminating instruction.
    #[must_use]
    pub fn terminating_insn(insn: impl Into<String>) -> Self {
        Self {
            kind: EvidenceKind::TerminatingInstruction,
            detail: Some(insn.into()),
            confidence: 0.95,
        }
    }

    /// Evidence from noreturn propagation.
    #[must_use]
    pub fn propagated(callee: Address) -> Self {
        Self {
            kind: EvidenceKind::PropagatedFromCallees,
            detail: Some(format!("callee {callee:#x}")),
            confidence: 0.85,
        }
    }

    /// User annotation.
    #[must_use]
    pub const fn user() -> Self {
        Self {
            kind: EvidenceKind::UserAnnotated,
            detail: None,
            confidence: 1.0,
        }
    }

    /// Evidence from a tail-call to a known-noreturn callee.
    #[must_use]
    pub fn tail_call_to_noreturn(callee: Address, via: &str) -> Self {
        Self {
            kind: EvidenceKind::TailCallToNoreturn,
            detail: Some(format!("tail {via} -> {callee:#x}")),
            confidence: 0.80,
        }
    }

    /// Returns `true` if confidence is above the given threshold.
    #[must_use]
    pub fn is_confident(&self, threshold: f32) -> bool {
        self.confidence >= threshold
    }
}

impl fmt::Display for NoreturnEvidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} (conf={:.2})", self.kind, self.confidence)?;
        if let Some(ref d) = self.detail {
            write!(f, ": {d}")?;
        }
        Ok(())
    }
}

// ── FunctionRecord ────────────────────────────────────────────────────────────

/// Minimal function descriptor needed by the detector.
#[derive(Debug, Clone)]
pub struct FunctionRecord {
    /// Function start address.
    pub address: Address,
    /// Optional name (from symbol table).
    pub name: Option<String>,
    /// Raw bytes of the function body.
    pub bytes: Vec<u8>,
    /// Addresses of functions that this function calls.
    pub callees: Vec<Address>,
    /// Whether this function is marked noreturn (initially from the user or
    /// symbol table; updated by the detector).
    pub is_noreturn: bool,
    /// Evidence collected so far.
    pub evidence: Vec<NoreturnEvidence>,
}

impl FunctionRecord {
    /// Create a new function record.
    #[must_use]
    pub const fn new(address: Address, bytes: Vec<u8>) -> Self {
        Self {
            address,
            name: None,
            bytes,
            callees: Vec::new(),
            is_noreturn: false,
            evidence: Vec::new(),
        }
    }

    /// Attach a name.
    #[must_use]
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Add a callee address.
    pub fn add_callee(&mut self, callee: Address) {
        if !self.callees.contains(&callee) {
            self.callees.push(callee);
        }
    }

    /// Mark the function as noreturn with the given evidence.
    pub fn mark_noreturn(&mut self, evidence: NoreturnEvidence) {
        self.is_noreturn = true;
        self.evidence.push(evidence);
    }

    /// Best confidence score across all evidence.
    #[must_use]
    pub fn best_confidence(&self) -> f32 {
        self.evidence
            .iter()
            .map(|e| e.confidence)
            .fold(0.0f32, f32::max)
    }
}

impl fmt::Display for FunctionRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = self.name.as_deref().unwrap_or("<unnamed>");
        write!(f, "fn {name} @ {:#x}", self.address.as_u64())?;
        if self.is_noreturn {
            write!(f, " [NORETURN]")?;
        }
        Ok(())
    }
}

// ── Static known-noreturn symbol database ─────────────────────────────────────

/// Well-known C/C++/Rust/OS symbols that are unconditionally noreturn.
///
/// Public so downstream crates (the decompiler signature emitter, MCP tools)
/// can seed their own noreturn caches from the same vocabulary.
pub static KNOWN_NORETURN_SYMBOLS: &[&str] = &[
    "abort",
    "_abort",
    "__abort",
    "exit",
    "_exit",
    "__exit",
    "quick_exit",
    "_Exit",
    "longjmp",
    "siglongjmp",
    "_longjmp",
    "__longjmp",
    "throw",
    "__cxa_throw",
    "__cxa_rethrow",
    "__stack_chk_fail",
    "__stack_smashing_detected",
    "terminate",
    "__terminate",
    "std::terminate",
    "std::abort",
    "ExitProcess",
    "TerminateProcess",
    "RtlExitUserProcess",
    "NtTerminateProcess",
    "pthread_exit",
    "thrd_exit",
    "_Noreturn_abort",
    "panic",                   // Rust
    "core::panicking::panic",  // Rust
    // Rust panic helpers — emitted by rustc for `panic!`, slice bounds checks,
    // arithmetic overflow, and the unwinding runtime.
    "panic_fmt",
    "panic_bounds_check",
    "core::panicking::panic_fmt",
    "core::panicking::panic_bounds_check",
    "core::panicking::panic_nounwind",
    "core::panicking::panic_nounwind_fmt",
    "rust_begin_unwind",
    "_Unwind_Resume",
    "__rust_start_panic",
    // Windows kernel32 / ntdll noreturn surface.
    "RaiseException",
    "RaiseFailFastException",
];

/// Returns `true` if `name` is a well-known noreturn symbol.
///
/// Matching is deliberately anchored. The previous rule accepted a bare
/// `name.contains(s)`, and the vocabulary contains `"exit"`, `"abort"`,
/// `"terminate"` and `"panic"` — so it classified as noreturn a set of very
/// ordinary functions that **do** return:
///
/// | symbol | why it returns |
/// |---|---|
/// | `atexit`, `_onexit`, `on_exit` | register a handler and return |
/// | `set_terminate` | installs a handler, returns the previous one |
/// | `set_abort_behavior` | sets a flag and returns |
///
/// The consequence is not cosmetic: a caller that believes a call never
/// returns stops following control flow after it, so **every instruction after
/// a call to `atexit` was discarded as unreachable** — and `atexit` appears in
/// the startup path of essentially every C program.
///
/// A candidate now matches only when it is the whole name, the final `::`
/// component, or a substring whose neighbours are not identifier characters
/// (so `std::terminate` matches, `set_terminate` does not). Itanium-mangled
/// names are still recognised through their `<len><name>` encoding.
#[must_use]
pub fn is_known_noreturn_symbol(name: &str) -> bool {
    KNOWN_NORETURN_SYMBOLS
        .iter()
        .any(|&s| symbol_matches_anchored(name, s))
}

/// `true` when `needle` occurs in `name` as a complete identifier rather than
/// as a fragment of a longer one.
fn symbol_matches_anchored(name: &str, needle: &str) -> bool {
    if needle.is_empty() {
        return false;
    }
    if name == needle {
        return true;
    }
    // Final `::` component, e.g. `std::terminate` for `terminate`.
    if name.rsplit("::").next() == Some(needle) {
        return true;
    }

    let is_ident = |c: u8| c.is_ascii_alphanumeric() || c == b'_';
    let bytes = name.as_bytes();
    let nlen = needle.len();

    for (start, _) in name.match_indices(needle) {
        let before = start.checked_sub(1).map(|i| bytes[i]);
        let after = bytes.get(start + nlen).copied();

        let left_ok = before.is_none_or(|c| !is_ident(c));
        let right_ok = after.is_none_or(|c| !is_ident(c));
        if left_ok && right_ok {
            return true;
        }

        // Itanium mangling encodes an identifier as `<length><name>`, so the
        // preceding bytes are digits rather than a separator — and the name is
        // FOLLOWED by more mangled text (`_ZSt9terminatev` ends in the `v` of
        // `void`), so `right_ok` must not be required here. The length prefix
        // is itself the delimiter, and requiring it to equal this identifier's
        // length is what distinguishes `_ZSt9terminatev` from an accidental
        // substring such as `_ZSt3exitv`.
        if before.is_some_and(|c| c.is_ascii_digit()) {
            let mut i = start;
            while i > 0 && bytes[i - 1].is_ascii_digit() {
                i -= 1;
            }
            if name[i..start].parse::<usize>() == Ok(nlen) {
                return true;
            }
        }
    }
    false
}

// ── Terminating instruction patterns ─────────────────────────────────────────

/// Check whether a byte slice contains an x86 terminating sequence near its end.
///
/// Scans the last `scan_window` bytes for `UD2` (0x0F 0x0B), `HLT` (0xF4),
/// or `INT3` clusters (≥4 consecutive 0xCC) that indicate the function never
/// returns.
#[must_use]
pub fn contains_terminating_insn_x86(bytes: &[u8], scan_window: usize) -> Option<String> {
    let start = bytes.len().saturating_sub(scan_window);
    let tail = &bytes[start..];

    // UD2 (0F 0B)
    for w in tail.windows(2) {
        if w == [0x0F, 0x0B] {
            return Some("UD2".to_string());
        }
    }
    // HLT
    if tail.contains(&0xF4) {
        return Some("HLT".to_string());
    }
    // INT3 cluster (≥4)
    let mut run = 0usize;
    for &b in tail {
        if b == 0xCC {
            run += 1;
            if run >= 4 {
                return Some("INT3-cluster".to_string());
            }
        } else {
            run = 0;
        }
    }
    None
}

/// Check whether an ARM64 function body ends with a terminating pattern.
/// ARM64 uses `UDF #0` (0x00 0x00 0x00 0x00) as an undefined instruction trap.
#[must_use]
pub fn contains_terminating_insn_arm64(bytes: &[u8]) -> Option<String> {
    if bytes.len() < 4 {
        return None;
    }
    let tail = &bytes[bytes.len() - 4..];
    let word = u32::from_le_bytes([tail[0], tail[1], tail[2], tail[3]]);
    // UDF #imm16: encoding 0x0000_0000 (imm=0) or generally top bits 0000_0000_0000_0000
    if word == 0x0000_0000 {
        return Some("UDF#0".to_string());
    }
    // BRK #0 (ARM64 debug trap): 0xD43E_0000
    if word == 0xD43E_0000 {
        return Some("BRK#0".to_string());
    }
    None
}

// ── Tail-transfer byte heuristic ─────────────────────────────────────────────

/// Classify the trailing transfer of a function body.
///
/// Returns `Some("jmp_rel32" | "jmp_indirect" | "call_no_ret")` when the
/// tail bytes look like an unconditional transfer that does not return:
///
/// * `E9 ?? ?? ?? ??` — `JMP rel32` as the last 5 bytes
/// * `FF /4` (`ModRM` reg field = 4) — indirect `JMP r/m`
/// * `E8 ?? ?? ?? ??` — `CALL rel32` as the last 5 bytes (no trailing `C3`)
///
/// Returns `None` for ARM64 (no tail-byte heuristic yet) and for x86 bodies
/// that end in `C3`/`C2` (RET) — those are normal returns, not tail-calls.
fn tail_transfer_kind(bytes: &[u8], arch: DetectorArch) -> Option<&'static str> {
    if !matches!(arch, DetectorArch::X86_64 | DetectorArch::X86_32) {
        // ARM64 tail BL/B classification would need full decoding; defer.
        return None;
    }
    let n = bytes.len();
    if n < 2 {
        return None;
    }
    let last = bytes[n - 1];
    // Strip trailing NOP/INT3 padding so a function followed by alignment
    // padding (`E9 .. .. .. ..  CC CC CC`) is still recognised as a tail JMP.
    let mut end = n;
    while end > 0 && matches!(bytes[end - 1], 0x90 | 0xCC) {
        end -= 1;
    }
    if end == 0 {
        return None;
    }
    let trimmed = &bytes[..end];
    let m = trimmed.len();
    // A real RET at the tail disqualifies the tail-call heuristic.
    if matches!(last, 0xC3 | 0xCB) {
        return None;
    }
    if m >= 5 && trimmed[m - 5] == 0xE9 {
        return Some("jmp_rel32");
    }
    if m >= 5 && trimmed[m - 5] == 0xE8 {
        // Trailing CALL with no RET after — caller cannot return.
        return Some("call_no_ret");
    }
    // FF /4 indirect JMP: opcode FF, ModRM.reg == 100b.
    if m >= 2 && trimmed[m - 2] == 0xFF {
        let modrm = trimmed[m - 1];
        let reg = (modrm >> 3) & 0x7;
        if reg == 4 {
            return Some("jmp_indirect");
        }
    }
    None
}

// ── NoreturnDetector ──────────────────────────────────────────────────────────

/// The main detector.
///
/// Works in three passes:
/// 1. **Symbol pass** — marks functions whose name is in the known-noreturn list.
/// 2. **Body pass** — marks functions whose body ends with a terminating instruction.
/// 3. **Propagation pass** — iteratively marks callers noreturn when all their
///    callees that diverge from normal control flow are themselves noreturn.
pub struct NoreturnDetector {
    /// All function records keyed by start address.
    functions: HashMap<u64, FunctionRecord>,
    /// Confidence threshold below which propagation is not accepted.
    pub propagation_threshold: f32,
    /// Architecture for body scanning.
    pub arch: DetectorArch,
    /// Scan window (bytes) for the body scan.
    pub scan_window: usize,
}

/// Architecture selector for the body scan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetectorArch {
    X86_64,
    X86_32,
    Arm64,
}

impl Default for NoreturnDetector {
    fn default() -> Self {
        Self {
            functions: HashMap::new(),
            propagation_threshold: 0.80,
            arch: DetectorArch::X86_64,
            scan_window: 32,
        }
    }
}

impl NoreturnDetector {
    /// Create a new detector.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the architecture.
    #[must_use]
    pub const fn with_arch(mut self, arch: DetectorArch) -> Self {
        self.arch = arch;
        self
    }

    /// Set the propagation confidence threshold.
    #[must_use]
    pub const fn with_threshold(mut self, t: f32) -> Self {
        self.propagation_threshold = t;
        self
    }

    // ── Mutation ──────────────────────────────────────────────────────────────

    /// Add a function record.
    pub fn add_function(&mut self, rec: FunctionRecord) {
        self.functions.insert(rec.address.as_u64(), rec);
    }

    /// Mark a function as noreturn with `UserAnnotated` evidence.
    ///
    /// # Errors
    /// [`NoreturnError::UnknownFunction`] when `addr` is not registered.
    pub fn mark_noreturn(&mut self, addr: Address) -> Result<(), NoreturnError> {
        self.functions
            .get_mut(&addr.as_u64())
            .ok_or(NoreturnError::UnknownFunction(addr))?
            .mark_noreturn(NoreturnEvidence::user());
        Ok(())
    }

    // ── Analysis ──────────────────────────────────────────────────────────────

    /// Run all four detection passes and return the set of noreturn function
    /// addresses discovered (including those that were pre-marked).
    pub fn run(&mut self) -> HashSet<u64> {
        self.pass_symbols();
        self.pass_body();
        self.pass_tail_call();
        self.propagate_noreturn();
        self.functions
            .values()
            .filter(|r| r.is_noreturn)
            .map(|r| r.address.as_u64())
            .collect()
    }

    /// Pass 1: mark functions by symbol name.
    pub fn pass_symbols(&mut self) {
        for rec in self.functions.values_mut() {
            if rec.is_noreturn {
                continue;
            }
            if let Some(name) = rec.name.clone()
                && is_known_noreturn_symbol(&name)
            {
                rec.mark_noreturn(NoreturnEvidence::known_symbol(name));
            }
        }
    }

    /// Pass 2: mark functions whose body ends with a terminating instruction.
    pub fn pass_body(&mut self) {
        for rec in self.functions.values_mut() {
            if rec.is_noreturn {
                continue;
            }
            let result = match self.arch {
                DetectorArch::X86_64 | DetectorArch::X86_32 => {
                    contains_terminating_insn_x86(&rec.bytes, self.scan_window)
                }
                DetectorArch::Arm64 => contains_terminating_insn_arm64(&rec.bytes),
            };
            if let Some(insn) = result {
                rec.mark_noreturn(NoreturnEvidence::terminating_insn(insn));
            }
        }
    }

    /// Pass 3: detect tail-calls to known-noreturn callees (gap H).
    ///
    /// A function `F` is marked noreturn if its last reachable instruction is
    /// an unconditional transfer (tail `JMP rel32`, indirect `JMP r/m`, or
    /// trailing `CALL rel32` with no following `RET`) targeting a callee that
    /// is already in the noreturn set.
    ///
    /// This complements `pass_body` (which only checks for `UD2`/`HLT`/`INT3`
    /// terminators) and runs **before** `propagate_noreturn` so that a chain
    /// of tail-calling thunks (`fn -> jmp panic_fmt`) all light up together.
    ///
    /// The detector relies on the caller having populated `FunctionRecord.callees`
    /// from disassembly. For the tail-byte heuristic to fire we additionally
    /// require the *last* callee in the list to match the tail target.
    ///
    /// # Panics
    ///
    /// Panics if a function record that passed the non-empty `callees` filter has
    /// an empty `callees` list (should be unreachable by construction).
    pub fn pass_tail_call(&mut self) {
        let noreturn_set: HashSet<u64> = self
            .functions
            .values()
            .filter(|r| r.is_noreturn)
            .map(|r| r.address.as_u64())
            .collect();

        if noreturn_set.is_empty() {
            return;
        }

        let candidates: Vec<u64> = self
            .functions
            .values()
            .filter(|r| !r.is_noreturn && !r.callees.is_empty())
            .map(|r| r.address.as_u64())
            .collect();

        for addr in candidates {
            let Some(rec) = self.functions.get(&addr) else {
                continue;
            };
            let last_callee = *rec.callees.last().expect("non-empty by filter");
            if !noreturn_set.contains(&last_callee.as_u64()) {
                continue;
            }

            // Tail-byte check: does the body end with a tail-transfer that
            // has no return following it?
            let bytes = rec.bytes.as_slice();
            let via = tail_transfer_kind(bytes, self.arch);
            let Some(kind) = via else {
                continue;
            };

            if let Some(r) = self.functions.get_mut(&addr) {
                r.mark_noreturn(NoreturnEvidence::tail_call_to_noreturn(last_callee, kind));
            }
        }
    }

    /// Pass 4: propagate noreturn up the call graph.
    ///
    /// A function is promoted to noreturn when every callee that is recorded as
    /// a call target (not a tail jump, which is handled by the splitter) is
    /// already noreturn.
    pub fn propagate_noreturn(&mut self) {
        // Work-list: start from all currently noreturn functions and propagate.
        let mut changed = true;
        while changed {
            changed = false;
            // Collect which addresses are noreturn.
            let noreturn_set: HashSet<u64> = self
                .functions
                .values()
                .filter(|r| r.is_noreturn)
                .map(|r| r.address.as_u64())
                .collect();

            // For each non-noreturn function, check if all callees are noreturn.
            let candidates: Vec<u64> = self
                .functions
                .values()
                .filter(|r| !r.is_noreturn && !r.callees.is_empty())
                .map(|r| r.address.as_u64())
                .collect();

            for addr in candidates {
                if let Some(rec) = self.functions.get(&addr) {
                    let all_callees_noreturn = !rec.callees.is_empty()
                        && rec.callees.iter().all(|c| noreturn_set.contains(&c.as_u64()));
                    if all_callees_noreturn {
                        // Collect the first callee address for evidence.
                        let first_callee = rec.callees[0];
                        if let Some(r) = self.functions.get_mut(&addr) {
                            r.mark_noreturn(NoreturnEvidence::propagated(first_callee));
                            changed = true;
                        }
                    }
                }
            }
        }
    }

    /// Returns `true` if the function at `addr` is noreturn.
    #[must_use]
    pub fn is_noreturn(&self, addr: Address) -> bool {
        self.functions
            .get(&addr.as_u64())
            .is_some_and(|r| r.is_noreturn)
    }

    /// Look up the evidence for `addr`.
    #[must_use]
    pub fn evidence_for(&self, addr: Address) -> Option<&[NoreturnEvidence]> {
        self.functions
            .get(&addr.as_u64())
            .map(|r| r.evidence.as_slice())
    }

    /// All noreturn function addresses.
    #[must_use]
    pub fn all_noreturn(&self) -> Vec<Address> {
        let mut v: Vec<Address> = self
            .functions
            .values()
            .filter(|r| r.is_noreturn)
            .map(|r| r.address)
            .collect();
        v.sort_by_key(|a| a.as_u64());
        v
    }

    /// Number of registered functions.
    #[must_use]
    pub fn function_count(&self) -> usize {
        self.functions.len()
    }

    /// Number of noreturn functions found so far.
    #[must_use]
    pub fn noreturn_count(&self) -> usize {
        self.functions.values().filter(|r| r.is_noreturn).count()
    }

    /// Return a map from address to evidence for all noreturn functions.
    #[must_use]
    pub fn report(&self) -> HashMap<u64, Vec<NoreturnEvidence>> {
        self.functions
            .values()
            .filter(|r| r.is_noreturn)
            .map(|r| (r.address.as_u64(), r.evidence.clone()))
            .collect()
    }

    /// BFS over the call graph from `root`, returning the reachable noreturn set.
    #[must_use]
    pub fn reachable_noreturn(&self, root: Address) -> Vec<Address> {
        let mut visited: HashSet<u64> = HashSet::new();
        let mut queue: VecDeque<u64> = VecDeque::new();
        queue.push_back(root.as_u64());
        let mut result = Vec::new();
        while let Some(addr) = queue.pop_front() {
            if !visited.insert(addr) {
                continue;
            }
            if let Some(rec) = self.functions.get(&addr) {
                if rec.is_noreturn {
                    result.push(rec.address);
                }
                for callee in &rec.callees {
                    queue.push_back(callee.as_u64());
                }
            }
        }
        result.sort_by_key(|a| a.as_u64());
        result
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_detector() -> NoreturnDetector {
        NoreturnDetector::new().with_arch(DetectorArch::X86_64)
    }

    #[test]
    fn known_noreturn_abort() {
        assert!(is_known_noreturn_symbol("abort"));
        assert!(is_known_noreturn_symbol("__cxa_throw"));
        assert!(is_known_noreturn_symbol("exit"));
        assert!(!is_known_noreturn_symbol("printf"));
    }

    #[test]
    fn known_noreturn_contains_path() {
        assert!(is_known_noreturn_symbol("core::panicking::panic"));
    }

    #[test]
    fn symbol_pass_marks_abort() {
        let mut det = make_detector();
        let rec = FunctionRecord::new(Address::new(0x1000), vec![0xC3])
            .with_name("abort");
        det.add_function(rec);
        det.pass_symbols();
        assert!(det.is_noreturn(Address::new(0x1000)));
    }

    #[test]
    fn body_pass_detects_ud2() {
        let mut det = make_detector();
        // Build a body ending with UD2 (0F 0B).
        let bytes = vec![0x55, 0x48, 0x89, 0xE5, 0x0F, 0x0B];
        let rec = FunctionRecord::new(Address::new(0x2000), bytes);
        det.add_function(rec);
        det.pass_body();
        assert!(det.is_noreturn(Address::new(0x2000)));
        let ev = det.evidence_for(Address::new(0x2000)).unwrap();
        assert!(ev.iter().any(|e| e.kind == EvidenceKind::TerminatingInstruction));
    }

    #[test]
    fn body_pass_detects_hlt() {
        let mut det = make_detector();
        let bytes = vec![0x90, 0xF4]; // NOP; HLT
        let rec = FunctionRecord::new(Address::new(0x3000), bytes);
        det.add_function(rec);
        det.pass_body();
        assert!(det.is_noreturn(Address::new(0x3000)));
    }

    #[test]
    fn propagation_marks_caller() {
        let mut det = make_detector();
        // Callee at 0x1000 is noreturn (abort).
        let callee = FunctionRecord::new(Address::new(0x1000), vec![0xC3]).with_name("abort");
        det.add_function(callee);
        det.pass_symbols();

        // Caller at 0x2000 calls only 0x1000.
        let mut caller = FunctionRecord::new(Address::new(0x2000), vec![0x90, 0xC3]);
        caller.add_callee(Address::new(0x1000));
        det.add_function(caller);

        det.propagate_noreturn();
        assert!(det.is_noreturn(Address::new(0x2000)));
        let ev = det.evidence_for(Address::new(0x2000)).unwrap();
        assert!(ev.iter().any(|e| e.kind == EvidenceKind::PropagatedFromCallees));
    }

    #[test]
    fn propagation_does_not_mark_partial_noreturn_caller() {
        let mut det = make_detector();
        // Two callees: only one is noreturn.
        let c1 = FunctionRecord::new(Address::new(0x1000), vec![0xC3]).with_name("abort");
        det.add_function(c1);
        det.pass_symbols();

        let c2 = FunctionRecord::new(Address::new(0x1100), vec![0xC3]); // normal
        det.add_function(c2);

        let mut caller = FunctionRecord::new(Address::new(0x2000), vec![0x90, 0xC3]);
        caller.add_callee(Address::new(0x1000));
        caller.add_callee(Address::new(0x1100));
        det.add_function(caller);

        det.propagate_noreturn();
        assert!(!det.is_noreturn(Address::new(0x2000)));
    }

    #[test]
    fn run_integrates_all_passes() {
        let mut det = make_detector();
        let rec = FunctionRecord::new(Address::new(0x1000), vec![0x0F, 0x0B]).with_name("crash");
        det.add_function(rec);
        let nr = det.run();
        assert!(nr.contains(&0x1000));
    }

    #[test]
    fn mark_noreturn_user_annotation() {
        let mut det = make_detector();
        let rec = FunctionRecord::new(Address::new(0x5000), vec![0xC3]);
        det.add_function(rec);
        det.mark_noreturn(Address::new(0x5000)).unwrap();
        assert!(det.is_noreturn(Address::new(0x5000)));
    }

    #[test]
    fn mark_noreturn_unknown_returns_error() {
        let mut det = make_detector();
        assert!(det.mark_noreturn(Address::new(0xDEAD)).is_err());
    }

    #[test]
    fn noreturn_count() {
        let mut det = make_detector();
        det.add_function(FunctionRecord::new(Address::new(0x1000), vec![0xC3]).with_name("exit"));
        det.add_function(FunctionRecord::new(Address::new(0x2000), vec![0xC3]));
        det.pass_symbols();
        assert_eq!(det.noreturn_count(), 1);
        assert_eq!(det.function_count(), 2);
    }

    #[test]
    fn report_returns_noreturn_map() {
        let mut det = make_detector();
        det.add_function(FunctionRecord::new(Address::new(0x1000), vec![0xC3]).with_name("abort"));
        det.pass_symbols();
        let report = det.report();
        assert!(report.contains_key(&0x1000));
    }

    #[test]
    fn evidence_display() {
        let ev = NoreturnEvidence::known_symbol("abort");
        let s = ev.to_string();
        assert!(s.contains("abort"));
        assert!(s.contains("1.00"));
    }

    #[test]
    fn terminating_insn_x86_no_match() {
        assert!(contains_terminating_insn_x86(&[0x90, 0x90, 0xC3], 32).is_none());
    }

    #[test]
    fn terminating_insn_arm64_udf() {
        let bytes = vec![0x00, 0x00, 0x00, 0x00];
        assert!(contains_terminating_insn_arm64(&bytes).is_some());
    }

    #[test]
    fn function_record_display() {
        let rec = FunctionRecord::new(Address::new(0xABCD), vec![]).with_name("foo");
        let s = rec.to_string();
        assert!(s.contains("foo"));
        assert!(s.contains("0xabcd") || s.contains("0xABCD"));
    }

    #[test]
    fn known_symbol_panic_fmt() {
        assert!(is_known_noreturn_symbol("panic_fmt"));
        assert!(is_known_noreturn_symbol("core::panicking::panic_bounds_check"));
        assert!(is_known_noreturn_symbol("RaiseException"));
        assert!(is_known_noreturn_symbol("_Unwind_Resume"));
    }

    #[test]
    fn tail_call_jmp_rel32_to_panic_fmt() {
        let mut det = make_detector();
        // Callee: panic_fmt (symbol-known noreturn).
        det.add_function(
            FunctionRecord::new(Address::new(0x4000), vec![0xC3]).with_name("panic_fmt"),
        );
        // Caller: short prologue + `JMP rel32` tail-call to panic_fmt.
        // Bytes: push rbp; mov rbp, rsp; jmp 0x4000  (rel32 placeholder).
        let bytes = vec![
            0x55, 0x48, 0x89, 0xE5, // prologue
            0xE9, 0x00, 0x00, 0x00, 0x00, // jmp rel32
        ];
        let mut caller = FunctionRecord::new(Address::new(0x5000), bytes);
        caller.add_callee(Address::new(0x4000));
        det.add_function(caller);

        let nr = det.run();
        assert!(nr.contains(&0x5000), "tail-call caller should be noreturn");
        let ev = det.evidence_for(Address::new(0x5000)).unwrap();
        assert!(
            ev.iter()
                .any(|e| e.kind == EvidenceKind::TailCallToNoreturn),
            "expected TailCallToNoreturn evidence, got {ev:?}"
        );
    }

    #[test]
    fn tail_call_skipped_when_body_ends_in_ret() {
        // Isolate the tail-call heuristic from the propagation pass by giving
        // the caller a second, *non*-noreturn callee. Then propagation cannot
        // fire — only the tail-byte check decides, and a trailing `C3` (RET)
        // must keep the function out of the noreturn set.
        let mut det = make_detector();
        det.add_function(
            FunctionRecord::new(Address::new(0x4000), vec![0xC3]).with_name("abort"),
        );
        det.add_function(FunctionRecord::new(Address::new(0x4100), vec![0xC3])); // normal
        // call abort; call other; ret
        let bytes = vec![
            0xE8, 0x00, 0x00, 0x00, 0x00, // call abort
            0xE8, 0x00, 0x00, 0x00, 0x00, // call other
            0xC3,                         // ret
        ];
        let mut caller = FunctionRecord::new(Address::new(0x5000), bytes);
        caller.add_callee(Address::new(0x4000));
        caller.add_callee(Address::new(0x4100));
        det.add_function(caller);

        det.run();
        assert!(!det.is_noreturn(Address::new(0x5000)));
    }

    #[test]
    fn tail_call_jmp_with_padding_after() {
        let mut det = make_detector();
        det.add_function(
            FunctionRecord::new(Address::new(0x4000), vec![0xC3]).with_name("rust_begin_unwind"),
        );
        // jmp rel32 followed by INT3 alignment padding.
        let bytes = vec![0xE9, 0x00, 0x00, 0x00, 0x00, 0xCC, 0xCC, 0xCC];
        let mut caller = FunctionRecord::new(Address::new(0x5000), bytes);
        caller.add_callee(Address::new(0x4000));
        det.add_function(caller);

        det.run();
        assert!(det.is_noreturn(Address::new(0x5000)));
    }

    #[test]
    fn tail_call_indirect_jmp_ff_slash_4() {
        let mut det = make_detector();
        det.add_function(
            FunctionRecord::new(Address::new(0x4000), vec![0xC3]).with_name("ExitProcess"),
        );
        // `jmp [rax]` = FF 20  (ModRM=0x20, reg=100b).
        let bytes = vec![0x48, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00, 0xFF, 0x20];
        let mut caller = FunctionRecord::new(Address::new(0x5000), bytes);
        caller.add_callee(Address::new(0x4000));
        det.add_function(caller);

        det.run();
        assert!(det.is_noreturn(Address::new(0x5000)));
    }

    use crate::{Confidence, DetectionSource, FunctionBoundary};

    fn fb(start: u64, end: Option<u64>, name: Option<&str>) -> FunctionBoundary {
        let mut b = FunctionBoundary::new(
            Address::new(start),
            Confidence::High,
            DetectionSource::ProloguePattern,
        );
        if let Some(e) = end {
            b = b.with_end(Address::new(e));
        }
        if let Some(n) = name {
            b = b.with_name(n);
        }
        b
    }

    #[test]
    fn detect_calls_abort() {
        let funcs = vec![
            fb(0x1000, Some(0x1010), Some("abort")),
            fb(0x2000, Some(0x2020), Some("crashy")),
        ];
        let xrefs = vec![(0x2010, 0x1000)];
        let hits = detect_noreturn_functions(&funcs, &xrefs);
        assert!(hits.iter().any(|h| h.addr == 0x2000 && h.reason == "calls_abort"));
    }

    /// The "`calls_abort`" heuristic (last call in the function body targets a
    /// noreturn symbol) must NOT depend on the order the xrefs happen to be
    /// passed in. A function that calls `abort()` and then a normal function has
    /// its *last* call to the normal function, so it returns — it must be
    /// classified identically regardless of xref input order.
    #[test]
    fn detect_calls_abort_is_order_independent() {
        let funcs = vec![
            fb(0x1000, Some(0x1010), Some("abort")),
            fb(0x1500, Some(0x1510), Some("normal_fn")),
            fb(0x2000, Some(0x2020), Some("crashy")),
        ];
        // crashy calls abort at site 0x2008, then normal_fn at site 0x2010.
        let abort_call = (0x2008u64, 0x1000u64);
        let normal_call = (0x2010u64, 0x1500u64);

        let hits_ab = detect_noreturn_functions(&funcs, &[abort_call, normal_call]);
        let hits_ba = detect_noreturn_functions(&funcs, &[normal_call, abort_call]);

        let flagged = |hits: &[NoReturnHit]| {
            hits.iter().any(|h| h.addr == 0x2000 && h.reason == "calls_abort")
        };
        assert_eq!(
            flagged(&hits_ab),
            flagged(&hits_ba),
            "calls_abort classification depends on xref input order"
        );
        // The last call by site address (0x2010) is to normal_fn, so crashy
        // returns from it and must NOT be flagged as calling abort.
        assert!(!flagged(&hits_ab), "crashy's last call is to normal_fn, not abort");
    }

    #[test]
    fn detect_ud2_name() {
        let funcs = vec![fb(0x3000, Some(0x3004), Some("__ud2_trap"))];
        let hits = detect_noreturn_functions(&funcs, &[]);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].reason, "ud2");
    }

    #[test]
    fn detect_infinite_loop_self_edge() {
        let funcs = vec![fb(0x4000, Some(0x4010), Some("spin"))];
        let xrefs = vec![(0x4008, 0x4000)];
        let hits = detect_noreturn_functions(&funcs, &xrefs);
        assert!(hits.iter().any(|h| h.addr == 0x4000 && h.reason == "infinite_loop"));
    }

    #[test]
    fn detect_no_ret_no_edges() {
        let funcs = vec![fb(0x5000, None, Some("dead_end"))];
        let hits = detect_noreturn_functions(&funcs, &[]);
        assert!(hits.iter().any(|h| h.addr == 0x5000 && h.reason == "no_ret"));
    }

    #[test]
    fn all_noreturn_sorted() {
        let mut det = make_detector();
        det.add_function(FunctionRecord::new(Address::new(0x3000), vec![0xC3]).with_name("exit"));
        det.add_function(FunctionRecord::new(Address::new(0x1000), vec![0xC3]).with_name("abort"));
        det.pass_symbols();
        let all = det.all_noreturn();
        assert_eq!(all[0].as_u64(), 0x1000);
        assert_eq!(all[1].as_u64(), 0x3000);
    }
}

#[cfg(test)]
mod noreturn_symbol_anchoring {
    use super::*;

    /// Functions that RETURN must not be classified as noreturn just because
    /// their name contains one of the vocabulary words.
    ///
    /// The matcher used to be `name.contains(s)` over a list holding "exit",
    /// "abort", "terminate" and "panic". A caller that believes a call never
    /// returns stops following control flow after it, so every instruction
    /// after a call to `atexit` — present in the startup path of essentially
    /// every C program — was discarded as unreachable.
    #[test]
    fn returning_functions_are_not_noreturn() {
        for name in [
            "atexit",
            "_onexit",
            "on_exit",
            "std::set_terminate",
            "set_terminate",
            "_set_abort_behavior",
            "exit_code",
            "panic_hook_installed",
            "throwaway",
            "printf",
        ] {
            assert!(
                !is_known_noreturn_symbol(name),
                "{name} returns, but was classified as noreturn"
            );
        }
    }

    /// Positive control: the real noreturn symbols must still be recognised,
    /// in plain, prefixed, namespaced and Itanium-mangled forms. Without this,
    /// answering `false` to everything would satisfy the test above and
    /// silently disable noreturn detection altogether.
    #[test]
    fn real_noreturn_symbols_are_still_recognised() {
        for name in [
            "abort",
            "_abort",
            "exit",
            "_exit",
            "quick_exit",
            "__cxa_throw",
            "std::terminate",
            "core::panicking::panic",
            "core::panicking::panic_bounds_check",
            "ExitProcess",
            "RaiseFailFastException",
            // Itanium mangling: `<len><name>` — 9 == "terminate".len().
            "_ZSt9terminatev",
        ] {
            assert!(
                is_known_noreturn_symbol(name),
                "{name} is noreturn but was not recognised"
            );
        }
    }

    /// The mangled-name rule must check the length prefix, not merely accept
    /// any digits: `_ZSt3exitv` claims a 3-character identifier, so the "exit"
    /// found there is not a complete symbol.
    #[test]
    fn mangled_length_prefix_must_agree_with_the_symbol() {
        assert!(
            is_known_noreturn_symbol("_ZSt4exitv"),
            "a correct length prefix (4 == exit.len()) must match"
        );
        assert!(
            !is_known_noreturn_symbol("_ZSt3exitv"),
            "a length prefix that disagrees must not match"
        );
    }
}
