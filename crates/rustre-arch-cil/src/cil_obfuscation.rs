//! `cil_obfuscation` — .NET CIL obfuscation detection and analysis.
//!
//! Provides:
//! * [`RenameObfuscation`]        — single-letter / mangled name detection
//! * [`ControlFlowObfuscation`]   — opaque predicates, junk code, fake branches
//! * [`StringEncryption`]         — encrypted/encoded string detection
//! * [`VirtualMachineObf`]        — VM-based obfuscation detection
//! * [`ObfuscationScore`]         — aggregate scoring
//! * [`CilObfuscation`]           — top-level facade

use std::collections::{HashMap, HashSet};
use std::fmt;

/// Re-exported map type for CIL obfuscation tables.
pub type CilObfMap<K, V> = HashMap<K, V>;
/// Re-exported formatter alias used by obfuscation diagnostics.
pub type CilObfFormatter<'a> = fmt::Formatter<'a>;

// ---------------------------------------------------------------------------
// Rename Obfuscation
// ---------------------------------------------------------------------------

/// Type of name mangling / obfuscation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NameObfuscationKind {
    /// Single printable letter names.
    SingleChar,
    /// Short names (2–3 chars).
    ShortName,
    /// Unicode-only names.
    UnicodeName,
    /// Control-character / unprintable names.
    UnprintableName,
    /// Names consisting only of lowercase L and capital I (look-alike).
    LookAlikeName,
    /// GUID-style names.
    GuidName,
    /// ProGuard-style a/b/c... sequences.
    ProGuardStyle,
}

/// A name that appears to be obfuscated.
#[derive(Debug, Clone)]
pub struct ObfuscatedName {
    pub name: String,
    pub kind: NameObfuscationKind,
    pub is_type: bool,
    pub is_method: bool,
    pub is_field: bool,
}

/// Rename obfuscation detector.
#[derive(Debug, Clone, Default)]
pub struct RenameObfuscation {
    /// Detected obfuscated names.
    pub obfuscated: Vec<ObfuscatedName>,
    /// Total names analyzed.
    pub total_analyzed: usize,
    /// Single-char name count.
    pub single_char_count: usize,
    /// Unprintable name count.
    pub unprintable_count: usize,
}

impl RenameObfuscation {
    /// Create a new detector.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Classify a name string.
    #[must_use]
    pub fn classify_name(name: &str) -> Option<NameObfuscationKind> {
        if name.is_empty() {
            return None;
        }
        if name.len() == 1 && name.chars().all(char::is_alphabetic) {
            return Some(NameObfuscationKind::SingleChar);
        }
        if name.chars().all(|c| !c.is_ascii_graphic() && c != ' ') {
            return Some(NameObfuscationKind::UnprintableName);
        }
        // ProGuard pattern: short all-lowercase ascii (a/b/ab/cd/...)
        if name.len() <= 2 && name.chars().all(|c| c.is_ascii_lowercase()) {
            return Some(NameObfuscationKind::ProGuardStyle);
        }
        // Check look-alike: all chars are 'l' or 'I' or '1' or 'O' or '0'
        if name.len() >= 4
            && name
                .chars()
                .all(|c| matches!(c, 'l' | 'I' | '1' | 'O' | '0'))
        {
            return Some(NameObfuscationKind::LookAlikeName);
        }
        // Short names (2 chars, contains uppercase) — anything not already caught above
        if name.len() <= 3 && name.chars().all(|c| c.is_lowercase() || c.is_uppercase())
            && name.len() < 3 {
                return Some(NameObfuscationKind::ShortName);
            }
        None
    }

    /// Analyze a single name.
    pub fn analyze(&mut self, name: &str, is_type: bool, is_method: bool, is_field: bool) {
        self.total_analyzed += 1;
        if let Some(kind) = Self::classify_name(name) {
            match kind {
                NameObfuscationKind::SingleChar => self.single_char_count += 1,
                NameObfuscationKind::UnprintableName => self.unprintable_count += 1,
                _ => {}
            }
            self.obfuscated.push(ObfuscatedName {
                name: name.to_string(),
                kind,
                is_type,
                is_method,
                is_field,
            });
        }
    }

    /// Fraction of names that are obfuscated (0.0–1.0).
    #[must_use]
    pub fn obfuscation_ratio(&self) -> f64 {
        if self.total_analyzed == 0 {
            0.0
        } else {
            count_f64(self.obfuscated.len()) / count_f64(self.total_analyzed)
        }
    }

    /// Share of analysed identifiers that look obfuscated, as a whole
    /// percentage in `0..=100`.
    ///
    /// Computed in integer arithmetic: unlike `obfuscation_ratio() * 100.0`
    /// it involves no float round-trip, so it can neither lose precision on
    /// large counts nor produce a value outside `0..=100`.
    #[must_use]
    pub fn obfuscation_percent(&self) -> u8 {
        percent_u8(self.obfuscated.len(), self.total_analyzed)
    }

    /// Whether significant rename obfuscation is present.
    #[must_use]
    pub fn is_obfuscated(&self) -> bool {
        self.obfuscation_ratio() > 0.3
    }
}

// ---------------------------------------------------------------------------
// Control Flow Obfuscation
// ---------------------------------------------------------------------------

/// Kind of control-flow obfuscation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CfObfKind {
    /// Opaque predicate (unconditional branch disguised as conditional).
    OpaquePredicate,
    /// Junk instructions / dead code inserted.
    JunkCode,
    /// Fake exception handler (try block used as branch).
    FakeException,
    /// Goto spaghetti — excessive unconditional branches.
    GotoSpaghetti,
    /// Tail call chaining to confuse decompilers.
    TailCallChain,
    /// Switch-based dispatcher (VM dispatcher pattern).
    SwitchDispatcher,
}

/// A control-flow obfuscation site.
#[derive(Debug, Clone)]
pub struct CfObfSite {
    pub address: u64,
    pub kind: CfObfKind,
    pub confidence: u8,
    pub description: String,
}

/// Control-flow obfuscation detector.
#[derive(Debug, Clone, Default)]
pub struct ControlFlowObfuscation {
    /// Detected sites.
    pub sites: Vec<CfObfSite>,
    /// Number of unconditional branches.
    pub unconditional_branches: usize,
    /// Number of conditional branches.
    pub conditional_branches: usize,
    /// Number of exception handlers.
    pub exception_handlers: usize,
    /// Whether a switch dispatcher was found.
    pub has_switch_dispatcher: bool,
}

impl ControlFlowObfuscation {
    /// Create a new detector.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a branch.
    pub const fn record_branch(&mut self, is_conditional: bool) {
        if is_conditional {
            self.conditional_branches += 1;
        } else {
            self.unconditional_branches += 1;
        }
    }

    /// Record an exception handler.
    pub fn record_exception_handler(&mut self, address: u64, is_fake: bool) {
        self.exception_handlers += 1;
        if is_fake {
            self.sites.push(CfObfSite {
                address,
                kind: CfObfKind::FakeException,
                confidence: 70,
                description: "Fake exception handler used as branch".to_string(),
            });
        }
    }

    /// Record an opaque predicate.
    pub fn record_opaque_predicate(&mut self, address: u64, confidence: u8) {
        self.sites.push(CfObfSite {
            address,
            kind: CfObfKind::OpaquePredicate,
            confidence,
            description: "Opaque predicate detected".to_string(),
        });
    }

    /// Compute goto spaghetti score (0–100).
    #[must_use]
    pub fn spaghetti_score(&self) -> u8 {
        let total = self.unconditional_branches + self.conditional_branches;
        if total == 0 {
            return 0;
        }
        // Computed in integer arithmetic, so there is no float round-trip and
        // the result is 0..=100 by construction.
        percent_u8(self.unconditional_branches, total)
    }

    /// Whether significant CF obfuscation was detected.
    #[must_use]
    pub fn is_obfuscated(&self) -> bool {
        !self.sites.is_empty() || self.spaghetti_score() > 60
    }

    /// Sites of a specific kind.
    #[must_use]
    pub fn sites_of_kind(&self, kind: CfObfKind) -> Vec<&CfObfSite> {
        self.sites.iter().filter(|s| s.kind == kind).collect()
    }
}

// ---------------------------------------------------------------------------
// String Encryption
// ---------------------------------------------------------------------------

/// A suspected encrypted string.
#[derive(Debug, Clone)]
pub struct EncryptedStringCandidate {
    /// Address where the string is referenced.
    pub reference_address: u64,
    /// Byte length of the candidate.
    pub byte_len: usize,
    /// Entropy (0.0–8.0).
    pub entropy: f64,
    /// Suspected decryption method.
    pub method: StringDecryptMethod,
}

/// Suspected string decryption method.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StringDecryptMethod {
    /// XOR with constant key.
    XorConstant,
    /// XOR with key array (rolling XOR).
    XorRolling,
    /// Base64 or other encoding.
    Encoded,
    /// Custom decrypt function call.
    CustomFunction,
    /// Unknown.
    Unknown,
}

/// String encryption detector.
#[derive(Debug, Clone, Default)]
pub struct StringEncryption {
    /// Candidate encrypted strings.
    pub candidates: Vec<EncryptedStringCandidate>,
    /// Number of high-entropy string regions found.
    pub high_entropy_regions: usize,
    /// Addresses of suspected decrypt functions.
    pub decrypt_functions: HashSet<u64>,
}

impl StringEncryption {
    /// Create a new detector.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Compute Shannon entropy of a byte slice.
    #[must_use]
    pub fn entropy(bytes: &[u8]) -> f64 {
        if bytes.is_empty() {
            return 0.0;
        }
        let mut freq = [0u32; 256];
        for &b in bytes {
            freq[b as usize] += 1;
        }
        let len = count_f64(bytes.len());
        freq.iter()
            .filter(|&&c| c > 0)
            .map(|&c| {
                let p = f64::from(c) / len;
                -p * p.log2()
            })
            .sum()
    }

    /// Check whether a byte sequence looks like an encrypted string.
    #[must_use]
    pub fn looks_encrypted(bytes: &[u8]) -> bool {
        if bytes.len() < 4 {
            return false;
        }
        let e = Self::entropy(bytes);
        e > 5.5
    }

    /// Record a candidate string.
    pub fn record_candidate(
        &mut self,
        reference_address: u64,
        bytes: &[u8],
        method: StringDecryptMethod,
    ) {
        let entropy = Self::entropy(bytes);
        if entropy > 4.0 {
            self.high_entropy_regions += 1;
        }
        self.candidates.push(EncryptedStringCandidate {
            reference_address,
            byte_len: bytes.len(),
            entropy,
            method,
        });
    }

    /// Register a suspected decryption function address.
    pub fn register_decrypt_function(&mut self, address: u64) {
        self.decrypt_functions.insert(address);
    }

    /// Whether encrypted strings were detected.
    #[must_use]
    pub const fn is_encrypted(&self) -> bool {
        !self.candidates.is_empty() && self.high_entropy_regions > 0
    }
}

// ---------------------------------------------------------------------------
// Virtual Machine Obfuscation
// ---------------------------------------------------------------------------

/// A VM opcode handler.
#[derive(Debug, Clone)]
pub struct VmHandler {
    /// Handler address.
    pub address: u64,
    /// VM opcode value.
    pub opcode: u32,
    /// Description if known.
    pub description: String,
}

/// VM-based obfuscation analysis.
#[derive(Debug, Clone, Default)]
pub struct VirtualMachineObf {
    /// Whether a VM dispatcher was detected.
    pub detected: bool,
    /// Dispatcher address.
    pub dispatcher_address: Option<u64>,
    /// VM handler table.
    pub handlers: Vec<VmHandler>,
    /// VM opcode fetch pattern count.
    pub opcode_fetch_count: usize,
    /// Confidence score (0–100).
    pub confidence: u8,
}

impl VirtualMachineObf {
    /// Create a new VM obfuscation detector.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a VM dispatcher.
    pub const fn record_dispatcher(&mut self, address: u64, confidence: u8) {
        self.detected = true;
        self.dispatcher_address = Some(address);
        self.confidence = confidence;
    }

    /// Register a VM handler.
    pub fn add_handler(&mut self, address: u64, opcode: u32, description: impl Into<String>) {
        self.handlers.push(VmHandler {
            address,
            opcode,
            description: description.into(),
        });
    }

    /// Record an opcode-fetch instruction pattern.
    pub fn record_opcode_fetch(&mut self) {
        self.opcode_fetch_count += 1;
        if self.opcode_fetch_count > 5 {
            self.detected = true;
            self.confidence = self.confidence.max(40);
        }
    }

    /// Number of VM handlers found.
    #[must_use]
    pub const fn handler_count(&self) -> usize {
        self.handlers.len()
    }

    /// Whether a dispatcher and handlers were both found.
    #[must_use]
    pub const fn is_vm_obfuscated(&self) -> bool {
        self.detected && (!self.handlers.is_empty() || self.confidence >= 50)
    }
}

// ---------------------------------------------------------------------------
// Obfuscation Score
// ---------------------------------------------------------------------------

/// Aggregate obfuscation score.
#[derive(Debug, Clone)]
pub struct ObfuscationScore {
    /// Rename obfuscation score (0–100).
    pub rename_score: u8,
    /// Control flow score (0–100).
    pub cf_score: u8,
    /// String encryption score (0–100).
    pub string_score: u8,
    /// VM protection score (0–100).
    pub vm_score: u8,
    /// Overall score (weighted average).
    pub overall: u8,
}

impl ObfuscationScore {
    /// Compute from component analyzers.
    #[must_use]
    pub fn compute(
        rename: &RenameObfuscation,
        cf: &ControlFlowObfuscation,
        strings: &StringEncryption,
        vm: &VirtualMachineObf,
    ) -> Self {
        let rename_score = rename.obfuscation_percent();
        let cf_score = if cf.is_obfuscated() {
            cf.spaghetti_score().max(50)
        } else {
            cf.spaghetti_score()
        };
        let string_score: u8 = if strings.is_encrypted() { 80 } else { 0 };
        let vm_score: u8 = vm.confidence;
        let overall = ((u32::from(rename_score) * 3
            + u32::from(cf_score) * 3
            + u32::from(string_score) * 2
            + u32::from(vm_score) * 2)
            / 10)
            .try_into()
            .unwrap_or(u8::MAX);
        Self {
            rename_score,
            cf_score,
            string_score,
            vm_score,
            overall,
        }
    }

    /// Obfuscation level description.
    #[must_use]
    pub const fn level(&self) -> &'static str {
        match self.overall {
            0..=20 => "clean",
            21..=40 => "lightly_obfuscated",
            41..=60 => "moderately_obfuscated",
            61..=80 => "heavily_obfuscated",
            _ => "extremely_obfuscated",
        }
    }
}

// ---------------------------------------------------------------------------
// Top-level facade
// ---------------------------------------------------------------------------

/// A CIL obfuscation analysis finding.
#[derive(Debug, Clone)]
pub struct ObfFinding {
    pub address: u64,
    pub message: String,
    pub confidence: u8,
}

/// Top-level CIL obfuscation analysis facade.
#[derive(Debug, Clone)]
pub struct CilObfuscation {
    /// Rename obfuscation analysis.
    pub rename: RenameObfuscation,
    /// Control flow obfuscation.
    pub cf: ControlFlowObfuscation,
    /// String encryption.
    pub strings: StringEncryption,
    /// VM protection.
    pub vm: VirtualMachineObf,
    /// Computed score.
    pub score: Option<ObfuscationScore>,
    /// Findings.
    pub findings: Vec<ObfFinding>,
    /// Total methods analyzed.
    pub total_methods: usize,
    /// Total types analyzed.
    pub total_types: usize,
}

impl Default for CilObfuscation {
    fn default() -> Self {
        Self::new()
    }
}

impl CilObfuscation {
    /// Create a new obfuscation analyzer.
    #[must_use]
    pub fn new() -> Self {
        Self {
            rename: RenameObfuscation::new(),
            cf: ControlFlowObfuscation::new(),
            strings: StringEncryption::new(),
            vm: VirtualMachineObf::new(),
            score: None,
            findings: Vec::new(),
            total_methods: 0,
            total_types: 0,
        }
    }

    /// Finalize and compute the aggregate score.
    pub fn finalize(&mut self) {
        self.score = Some(ObfuscationScore::compute(
            &self.rename,
            &self.cf,
            &self.strings,
            &self.vm,
        ));
    }

    /// Record a type or method name for rename analysis.
    pub fn record_name(&mut self, name: &str, is_type: bool, is_method: bool, is_field: bool) {
        if is_type {
            self.total_types += 1;
        }
        if is_method {
            self.total_methods += 1;
        }
        self.rename.analyze(name, is_type, is_method, is_field);
    }

    /// Record a branch in a method.
    pub const fn record_branch(&mut self, is_conditional: bool) {
        self.cf.record_branch(is_conditional);
    }

    /// Record an encrypted string candidate.
    pub fn record_encrypted_string(&mut self, addr: u64, bytes: &[u8]) {
        self.strings
            .record_candidate(addr, bytes, StringDecryptMethod::Unknown);
        if StringEncryption::looks_encrypted(bytes) {
            self.findings.push(ObfFinding {
                address: addr,
                message: "high-entropy string".to_string(),
                confidence: 70,
            });
        }
    }

    /// Overall obfuscation level (requires `finalize()` to have been called).
    #[must_use]
    pub fn level(&self) -> &'static str {
        self.score.as_ref().map_or("unknown", |s| s.level())
    }

    /// Whether any significant obfuscation was detected.
    #[must_use]
    pub fn is_obfuscated(&self) -> bool {
        self.rename.is_obfuscated()
            || self.cf.is_obfuscated()
            || self.strings.is_encrypted()
            || self.vm.is_vm_obfuscated()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// `part / whole` expressed as a whole percentage, clamped to `0..=100`.
///
/// Integer-only, so it is exact for every `usize` input and cannot panic:
/// a zero `whole` yields 0 rather than dividing by zero.
fn percent_u8(part: usize, whole: usize) -> u8 {
    if whole == 0 {
        return 0;
    }
    let pct = part.saturating_mul(100) / whole;
    u8::try_from(pct.min(100)).unwrap_or(100)
}

/// A count widened to `f64` for a ratio.
///
/// Clamped to `u32::MAX` first, so the widening is *exact*: every `u32` is
/// representable in an `f64`. No CIL artefact carries more than four billion
/// identifiers or bytes, and clamping is preferable to the silent rounding a
/// direct `usize as f64` would perform above 2^53.
fn count_f64(n: usize) -> f64 {
    f64::from(u32::try_from(n).unwrap_or(u32::MAX))
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── RenameObfuscation ─────────────────────────────────────────────────────

    #[test]
    fn test_rename_classify_single_char() {
        assert_eq!(
            RenameObfuscation::classify_name("a"),
            Some(NameObfuscationKind::SingleChar)
        );
        assert_eq!(
            RenameObfuscation::classify_name("Z"),
            Some(NameObfuscationKind::SingleChar)
        );
    }

    #[test]
    fn test_rename_classify_short() {
        assert_eq!(
            RenameObfuscation::classify_name("ab"),
            Some(NameObfuscationKind::ProGuardStyle)
        );
    }

    #[test]
    fn test_rename_classify_look_alike() {
        assert_eq!(
            RenameObfuscation::classify_name("lIlI"),
            Some(NameObfuscationKind::LookAlikeName)
        );
    }

    #[test]
    fn test_rename_classify_normal_name() {
        assert!(RenameObfuscation::classify_name("ProcessData").is_none());
        assert!(RenameObfuscation::classify_name("CustomerRepository").is_none());
    }

    #[test]
    fn test_rename_obfuscation_ratio() {
        let mut r = RenameObfuscation::new();
        r.analyze("a", true, false, false);
        r.analyze("b", false, true, false);
        r.analyze("NormalName", true, false, false);
        r.analyze("AnotherNormal", false, true, false);
        let ratio = r.obfuscation_ratio();
        assert!((ratio - 0.5).abs() < 1e-9);
    }

    #[test]
    fn test_rename_is_obfuscated_threshold() {
        let mut r = RenameObfuscation::new();
        for _ in 0..4 {
            r.analyze("a", true, false, false);
        }
        for _ in 0..6 {
            r.analyze("LongName", true, false, false);
        }
        // 4/10 = 0.4 > 0.3 → obfuscated
        assert!(r.is_obfuscated());
    }

    #[test]
    fn test_rename_not_obfuscated() {
        let mut r = RenameObfuscation::new();
        for _ in 0..10 {
            r.analyze("NormalName", true, false, false);
        }
        assert!(!r.is_obfuscated());
    }

    // ── ControlFlowObfuscation ────────────────────────────────────────────────

    #[test]
    fn test_cf_spaghetti_score_empty() {
        let cf = ControlFlowObfuscation::new();
        assert_eq!(cf.spaghetti_score(), 0);
    }

    #[test]
    fn test_cf_spaghetti_score_all_unconditional() {
        let mut cf = ControlFlowObfuscation::new();
        for _ in 0..10 {
            cf.record_branch(false);
        }
        assert_eq!(cf.spaghetti_score(), 100);
    }

    #[test]
    fn test_cf_record_opaque_predicate() {
        let mut cf = ControlFlowObfuscation::new();
        cf.record_opaque_predicate(0x1000, 80);
        assert!(cf.is_obfuscated());
        assert_eq!(cf.sites_of_kind(CfObfKind::OpaquePredicate).len(), 1);
    }

    #[test]
    fn test_cf_record_fake_exception() {
        let mut cf = ControlFlowObfuscation::new();
        cf.record_exception_handler(0x2000, true);
        assert_eq!(cf.sites_of_kind(CfObfKind::FakeException).len(), 1);
    }

    #[test]
    fn test_cf_not_obfuscated_initially() {
        let cf = ControlFlowObfuscation::new();
        assert!(!cf.is_obfuscated());
    }

    // ── StringEncryption ──────────────────────────────────────────────────────

    #[test]
    fn test_entropy_zero_for_uniform() {
        let bytes = vec![0xAAu8; 16];
        // A single repeated byte carries no information; compare against an
        // epsilon rather than for bit equality.
        assert!(StringEncryption::entropy(&bytes).abs() < f64::EPSILON);
    }

    #[test]
    fn test_entropy_max_for_random() {
        // All 256 byte values — max entropy = 8.0
        let bytes: Vec<u8> = (0..=255u8).collect();
        let e = StringEncryption::entropy(&bytes);
        assert!((e - 8.0).abs() < 0.001);
    }

    #[test]
    fn test_entropy_ascii_text() {
        let text = b"Hello, World!";
        let e = StringEncryption::entropy(text);
        assert!(e > 2.0 && e < 6.0);
    }

    #[test]
    fn test_looks_encrypted_high_entropy() {
        let bytes: Vec<u8> = (0u8..200).collect();
        assert!(StringEncryption::looks_encrypted(&bytes));
    }

    #[test]
    fn test_looks_encrypted_plain_text() {
        let bytes = b"Hello World this is plain text";
        assert!(!StringEncryption::looks_encrypted(bytes));
    }

    #[test]
    fn test_string_encryption_record_candidate() {
        let mut se = StringEncryption::new();
        let bytes: Vec<u8> = (0..200u8).collect();
        se.record_candidate(0x1000, &bytes, StringDecryptMethod::XorConstant);
        assert_eq!(se.candidates.len(), 1);
    }

    #[test]
    fn test_string_encryption_register_decrypt_fn() {
        let mut se = StringEncryption::new();
        se.register_decrypt_function(0x5000);
        assert!(se.decrypt_functions.contains(&0x5000));
    }

    // ── VirtualMachineObf ─────────────────────────────────────────────────────

    #[test]
    fn test_vm_record_dispatcher() {
        let mut vm = VirtualMachineObf::new();
        vm.record_dispatcher(0x1000, 80);
        assert!(vm.detected);
        assert_eq!(vm.confidence, 80);
    }

    #[test]
    fn test_vm_add_handler() {
        let mut vm = VirtualMachineObf::new();
        vm.add_handler(0x2000, 0x01, "LOAD");
        vm.add_handler(0x2010, 0x02, "ADD");
        assert_eq!(vm.handler_count(), 2);
    }

    #[test]
    fn test_vm_record_opcode_fetch() {
        let mut vm = VirtualMachineObf::new();
        for _ in 0..6 {
            vm.record_opcode_fetch();
        }
        assert!(vm.detected);
    }

    #[test]
    fn test_vm_not_detected_initially() {
        let vm = VirtualMachineObf::new();
        assert!(!vm.is_vm_obfuscated());
    }

    #[test]
    fn test_vm_is_obfuscated_with_dispatcher_and_handlers() {
        let mut vm = VirtualMachineObf::new();
        vm.record_dispatcher(0x1000, 90);
        vm.add_handler(0x2000, 1, "NOP");
        assert!(vm.is_vm_obfuscated());
    }

    // ── ObfuscationScore ──────────────────────────────────────────────────────

    #[test]
    fn test_score_clean_binary() {
        let r = RenameObfuscation::new();
        let cf = ControlFlowObfuscation::new();
        let s = StringEncryption::new();
        let v = VirtualMachineObf::new();
        let score = ObfuscationScore::compute(&r, &cf, &s, &v);
        assert_eq!(score.level(), "clean");
    }

    #[test]
    fn test_score_with_rename() {
        let mut r = RenameObfuscation::new();
        for _ in 0..8 {
            r.analyze("a", true, false, false);
        }
        for _ in 0..2 {
            r.analyze("Normal", true, false, false);
        }
        let cf = ControlFlowObfuscation::new();
        let s = StringEncryption::new();
        let v = VirtualMachineObf::new();
        let score = ObfuscationScore::compute(&r, &cf, &s, &v);
        assert!(score.rename_score >= 70);
    }

    #[test]
    fn test_score_level_names() {
        let score = ObfuscationScore {
            rename_score: 90,
            cf_score: 90,
            string_score: 80,
            vm_score: 80,
            overall: 85,
        };
        assert_eq!(score.level(), "extremely_obfuscated");
    }

    // ── CilObfuscation ────────────────────────────────────────────────────────

    #[test]
    fn test_cil_record_name() {
        let mut c = CilObfuscation::new();
        c.record_name("a", true, false, false);
        c.record_name("b", false, true, false);
        assert_eq!(c.total_types, 1);
        assert_eq!(c.total_methods, 1);
    }

    #[test]
    fn test_cil_finalize_computes_score() {
        let mut c = CilObfuscation::new();
        c.finalize();
        assert!(c.score.is_some());
    }

    #[test]
    fn test_cil_level_after_finalize() {
        let mut c = CilObfuscation::new();
        c.finalize();
        assert_eq!(c.level(), "clean");
    }

    #[test]
    fn test_cil_not_obfuscated_empty() {
        let c = CilObfuscation::new();
        assert!(!c.is_obfuscated());
    }

    #[test]
    fn test_cil_record_encrypted_string() {
        let mut c = CilObfuscation::new();
        let high_entropy: Vec<u8> = (0..200u8).collect();
        c.record_encrypted_string(0x1000, &high_entropy);
        assert_eq!(c.findings.len(), 1);
    }

    #[test]
    fn test_cil_record_branch() {
        let mut c = CilObfuscation::new();
        c.record_branch(true);
        c.record_branch(false);
        assert_eq!(c.cf.conditional_branches, 1);
        assert_eq!(c.cf.unconditional_branches, 1);
    }

    // ── Additional coverage ───────────────────────────────────────────────────

    #[test]
    fn test_rename_single_char_count() {
        let mut r = RenameObfuscation::new();
        r.analyze("a", true, false, false);
        r.analyze("b", false, true, false);
        r.analyze("c", false, false, true);
        assert_eq!(r.single_char_count, 3);
    }

    #[test]
    fn test_cf_mixed_branches_ratio() {
        let mut cf = ControlFlowObfuscation::new();
        for _ in 0..3 {
            cf.record_branch(false);
        } // unconditional
        for _ in 0..7 {
            cf.record_branch(true);
        } // conditional
        let score = cf.spaghetti_score();
        assert_eq!(score, 30); // 3/10 = 30%
    }

    #[test]
    fn test_string_encryption_not_encrypted_initially() {
        let se = StringEncryption::new();
        assert!(!se.is_encrypted());
    }

    #[test]
    fn test_vm_handler_count_empty() {
        let vm = VirtualMachineObf::new();
        assert_eq!(vm.handler_count(), 0);
        assert!(!vm.is_vm_obfuscated());
    }

    #[test]
    fn test_score_levels() {
        let make = |overall| ObfuscationScore {
            rename_score: 0,
            cf_score: 0,
            string_score: 0,
            vm_score: 0,
            overall,
        };
        assert_eq!(make(10).level(), "clean");
        assert_eq!(make(30).level(), "lightly_obfuscated");
        assert_eq!(make(50).level(), "moderately_obfuscated");
        assert_eq!(make(70).level(), "heavily_obfuscated");
        assert_eq!(make(90).level(), "extremely_obfuscated");
    }

    #[test]
    fn test_cil_is_obfuscated_with_vm() {
        let mut c = CilObfuscation::new();
        c.vm.record_dispatcher(0x1000, 90);
        c.vm.add_handler(0x2000, 1, "NOP");
        assert!(c.is_obfuscated());
    }
}
