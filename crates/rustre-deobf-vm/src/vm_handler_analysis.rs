//! VM Handler Pattern Analysis
//!
//! Detects and classifies handlers for five major commercial protectors:
//! - VMProtect 2.x / 3.x
//! - Themida / WinLicense
//! - Code Virtualizer
//! - Enigma Protector
//! - Obsidium
//!
//! Also provides semantic classification of handler bodies into the canonical
//! VM operations: PUSH, POP, ADD, SUB, AND, OR, XOR, NOT, SHL, SHR, JCC, CALL, RET.


use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ─────────────────────────────────────────────────────────────────────────────
// Error type
// ─────────────────────────────────────────────────────────────────────────────

/// Errors from handler analysis.
#[derive(Debug, Error)]
pub enum HandlerAnalysisError {
    #[error("handler body is too short ({len} bytes; minimum {min})")]
    BodyTooShort { len: usize, min: usize },

    #[error("binary slice is empty")]
    EmptyBinary,

    #[error("unsupported pointer size {size}; expected 4 or 8")]
    BadPointerSize { size: u8 },

    #[error("no handler candidates found above confidence threshold {threshold:.2}")]
    NoCandidates { threshold: f32 },
}

// ─────────────────────────────────────────────────────────────────────────────
// HandlerSemantic — canonical VM operation
// ─────────────────────────────────────────────────────────────────────────────

/// Semantic meaning of a VM handler body.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum HandlerSemantic {
    /// Push an immediate or register value onto the VM stack.
    Push,
    /// Pop the top-of-stack into a VM register or memory location.
    Pop,
    /// Binary addition (stack-based: TOS + NOS → result pushed).
    Add,
    /// Binary subtraction (NOS − TOS → result pushed).
    Sub,
    /// Binary multiplication.
    Mul,
    /// Unsigned division.
    Div,
    /// Bitwise AND.
    And,
    /// Bitwise OR.
    Or,
    /// Bitwise XOR.
    Xor,
    /// Bitwise NOT (one's complement).
    Not,
    /// Arithmetic negate (two's complement).
    Neg,
    /// Logical shift left.
    Shl,
    /// Logical shift right.
    Shr,
    /// Arithmetic shift right.
    Sar,
    /// Rotate left.
    Rol,
    /// Rotate right.
    Ror,
    /// Load from virtual memory.
    Load,
    /// Store to virtual memory.
    Store,
    /// Unconditional jump.
    Jmp,
    /// Conditional jump (JCC equivalent).
    Jcc,
    /// VM-level CALL (pushes return VIP and jumps).
    Call,
    /// VM-level RET (pops return VIP and jumps).
    Ret,
    /// Compare and set flags.
    Cmp,
    /// No-operation.
    Nop,
    /// Exit the VM (return to native code).
    VmExit,
    /// Enter the VM (native-to-VM transition).
    VmEnter,
    /// Fetch the native flags register and push.
    PushFlags,
    /// Pop and write the native flags register.
    PopFlags,
    /// Unknown / not yet classified.
    Unknown,
}

impl HandlerSemantic {
    /// Returns `true` if this semantic affects control flow.
    pub fn is_control_flow(self) -> bool {
        matches!(
            self,
            Self::Jmp | Self::Jcc | Self::Call | Self::Ret | Self::VmExit | Self::VmEnter
        )
    }

    /// Returns `true` if this semantic is a binary ALU operation.
    pub fn is_binary_alu(self) -> bool {
        matches!(
            self,
            Self::Add
                | Self::Sub
                | Self::Mul
                | Self::Div
                | Self::And
                | Self::Or
                | Self::Xor
                | Self::Shl
                | Self::Shr
                | Self::Sar
                | Self::Rol
                | Self::Ror
        )
    }

    /// Human-readable mnemonic.
    pub fn mnemonic(self) -> &'static str {
        match self {
            Self::Push => "PUSH",
            Self::Pop => "POP",
            Self::Add => "ADD",
            Self::Sub => "SUB",
            Self::Mul => "MUL",
            Self::Div => "DIV",
            Self::And => "AND",
            Self::Or => "OR",
            Self::Xor => "XOR",
            Self::Not => "NOT",
            Self::Neg => "NEG",
            Self::Shl => "SHL",
            Self::Shr => "SHR",
            Self::Sar => "SAR",
            Self::Rol => "ROL",
            Self::Ror => "ROR",
            Self::Load => "LOAD",
            Self::Store => "STORE",
            Self::Jmp => "JMP",
            Self::Jcc => "JCC",
            Self::Call => "CALL",
            Self::Ret => "RET",
            Self::Cmp => "CMP",
            Self::Nop => "NOP",
            Self::VmExit => "VM_EXIT",
            Self::VmEnter => "VM_ENTER",
            Self::PushFlags => "PUSHF",
            Self::PopFlags => "POPF",
            Self::Unknown => "???",
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// HandlerCandidate
// ─────────────────────────────────────────────────────────────────────────────

/// A detected VM handler candidate with its classification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandlerCandidate {
    /// Address of the handler in the binary (file offset or VA).
    pub address: u64,
    /// Raw bytes of the handler body (up to 64 bytes).
    pub body: Vec<u8>,
    /// Classified semantic.
    pub semantic: HandlerSemantic,
    /// Number of stack values consumed.
    pub stack_pop_count: u8,
    /// Number of stack values produced.
    pub stack_push_count: u8,
    /// Confidence in the classification [0.0, 1.0].
    pub confidence: f32,
    /// Evidence strings contributing to classification.
    pub evidence: Vec<String>,
    /// Estimated size of the handler in bytes.
    pub estimated_size: usize,
    /// Whether the handler contains obfuscating junk instructions (junk NOP sleds etc.)
    pub has_junk_code: bool,
}

impl HandlerCandidate {
    /// Create a minimal candidate.
    pub fn new(address: u64, body: Vec<u8>) -> Self {
        Self {
            address,
            body,
            semantic: HandlerSemantic::Unknown,
            stack_pop_count: 0,
            stack_push_count: 0,
            confidence: 0.0,
            evidence: Vec::new(),
            estimated_size: 0,
            has_junk_code: false,
        }
    }

    /// Stack delta (push_count − pop_count).
    pub fn stack_delta(&self) -> i32 {
        self.stack_push_count as i32 - self.stack_pop_count as i32
    }

    /// Add an evidence string.
    pub fn add_evidence(&mut self, ev: impl Into<String>) {
        self.evidence.push(ev.into());
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ProtectorDetectionResult
// ─────────────────────────────────────────────────────────────────────────────

/// Identifies which commercial protector's handler patterns were found.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DetectedProtector {
    VMProtect2,
    VMProtect3,
    Themida,
    WinLicense,
    CodeVirtualizer,
    Enigma,
    Obsidium,
    Custom,
    Unknown,
}

impl DetectedProtector {
    /// Returns the display name.
    pub fn name(&self) -> &'static str {
        match self {
            Self::VMProtect2 => "VMProtect 2.x",
            Self::VMProtect3 => "VMProtect 3.x",
            Self::Themida => "Themida",
            Self::WinLicense => "WinLicense",
            Self::CodeVirtualizer => "Code Virtualizer",
            Self::Enigma => "Enigma Protector",
            Self::Obsidium => "Obsidium",
            Self::Custom => "Custom VM",
            Self::Unknown => "Unknown",
        }
    }

    /// Whether this protector uses stack-based VM semantics.
    pub fn is_stack_based(&self) -> bool {
        matches!(
            self,
            Self::VMProtect2 | Self::VMProtect3 | Self::Themida | Self::WinLicense
        )
    }

    /// Typical handler table entry count range.
    pub fn handler_count_range(&self) -> (usize, usize) {
        match self {
            Self::VMProtect2 => (100, 220),
            Self::VMProtect3 => (150, 280),
            Self::Themida => (80, 200),
            Self::WinLicense => (80, 200),
            Self::CodeVirtualizer => (20, 80),
            Self::Enigma => (30, 120),
            Self::Obsidium => (50, 150),
            Self::Custom => (4, 512),
            Self::Unknown => (4, 512),
        }
    }
}

/// Result of a single-protector detection pass.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtectorDetectionResult {
    /// Which protector was detected.
    pub protector: DetectedProtector,
    /// Confidence score [0.0, 1.0].
    pub confidence: f32,
    /// Matched handler candidates.
    pub handlers: Vec<HandlerCandidate>,
    /// Evidence items.
    pub evidence: Vec<String>,
    /// VM entry stub address (if found).
    pub vm_entry_addr: Option<u64>,
    /// Handler table address (if found).
    pub handler_table_addr: Option<u64>,
}

impl ProtectorDetectionResult {
    /// Create a new result.
    pub fn new(protector: DetectedProtector) -> Self {
        Self {
            protector,
            confidence: 0.0,
            handlers: Vec::new(),
            evidence: Vec::new(),
            vm_entry_addr: None,
            handler_table_addr: None,
        }
    }

    /// Returns `true` if this is a high-confidence detection.
    pub fn is_high_confidence(&self) -> bool {
        self.confidence >= 0.70
    }

    /// Add an evidence item.
    pub fn add_evidence(&mut self, ev: impl Into<String>) {
        self.evidence.push(ev.into());
    }

    /// Number of successfully classified handlers.
    pub fn classified_count(&self) -> usize {
        self.handlers
            .iter()
            .filter(|h| h.semantic != HandlerSemantic::Unknown)
            .count()
    }

    /// Group the candidate handlers by their classified [`HandlerSemantic`].
    /// Useful for summarising the protector's instruction mix.
    pub fn handlers_by_semantic(&self) -> HashMap<HandlerSemantic, Vec<&HandlerCandidate>> {
        let mut out: HashMap<HandlerSemantic, Vec<&HandlerCandidate>> = HashMap::new();
        for h in &self.handlers {
            out.entry(h.semantic).or_default().push(h);
        }
        out
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// VmHandlerAnalyzer — top-level analyser
// ─────────────────────────────────────────────────────────────────────────────

/// Configuration for the handler analyser.
#[derive(Debug, Clone)]
pub struct HandlerAnalyzerConfig {
    /// Minimum confidence to accept a detection.
    pub min_confidence: f32,
    /// Maximum number of handler candidates to analyse.
    pub max_handlers: usize,
    /// Size of the binary window to sample for each protector check.
    pub sample_size: usize,
    /// Whether to run junk-code detection.
    pub detect_junk: bool,
}

impl Default for HandlerAnalyzerConfig {
    fn default() -> Self {
        Self {
            min_confidence: 0.30,
            max_handlers: 512,
            sample_size: 0x80000,
            detect_junk: true,
        }
    }
}

/// Top-level VM handler analyser.
///
/// Runs all five protector-specific detectors and returns results sorted by confidence.
#[derive(Debug, Clone, Default)]
pub struct VmHandlerAnalyzer {
    pub config: HandlerAnalyzerConfig,
}

impl VmHandlerAnalyzer {
    /// Create an analyser with default configuration.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create an analyser with custom configuration.
    pub fn with_config(config: HandlerAnalyzerConfig) -> Self {
        Self { config }
    }

    /// Run all detectors against `binary` and return every detection whose
    /// confidence exceeds the configured minimum.
    pub fn analyze(
        &self,
        binary: &[u8],
    ) -> Result<Vec<ProtectorDetectionResult>, HandlerAnalysisError> {
        if binary.is_empty() {
            return Err(HandlerAnalysisError::EmptyBinary);
        }

        let mut results = Vec::new();

        if let Some(r) = self.detect_vmprotect(binary)
            && r.confidence >= self.config.min_confidence {
                results.push(r);
            }
        if let Some(r) = self.detect_themida(binary)
            && r.confidence >= self.config.min_confidence {
                results.push(r);
            }
        if let Some(r) = self.detect_codevirtualizer(binary)
            && r.confidence >= self.config.min_confidence {
                results.push(r);
            }
        if let Some(r) = self.detect_enigma(binary)
            && r.confidence >= self.config.min_confidence {
                results.push(r);
            }
        if let Some(r) = self.detect_obsidium(binary)
            && r.confidence >= self.config.min_confidence {
                results.push(r);
            }

        results.sort_by(|a, b| {
            b.confidence
                .partial_cmp(&a.confidence)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        Ok(results)
    }

    // ── VMProtect ─────────────────────────────────────────────────────────────

    /// Detect VMProtect (2.x or 3.x) handler patterns.
    ///
    /// VMProtect uses a dispatcher that fetches an opcode byte from `[ESI/RSI]`,
    /// advances ESI/RSI by the instruction size, and jumps through a handler table
    /// indexed by the opcode. Handlers are small (20-150 bytes), densely packed, and
    /// end with `JMP [handler_table + opcode * 8]` or `JMP [EAX/RAX]`.
    pub fn detect_vmprotect(&self, binary: &[u8]) -> Option<ProtectorDetectionResult> {
        let mut result = ProtectorDetectionResult::new(DetectedProtector::VMProtect2);

        // Signal 1: ".vmp0" / ".vmp1" section name strings in the binary.
        if contains_bytes(binary, b".vmp0") {
            result.add_evidence("Section name '.vmp0' found");
            result.confidence += 0.40;
        }
        if contains_bytes(binary, b".vmp1") {
            result.add_evidence("Section name '.vmp1' found");
            result.confidence += 0.20;
        }

        // Signal 2: VMProtect string markers.
        for marker in [b"VMProtect".as_slice(), b"vmp_begin", b"vmp_end"] {
            if contains_bytes(binary, marker) {
                result.add_evidence(format!(
                    "Marker '{}' found",
                    std::str::from_utf8(marker).unwrap_or("?")
                ));
                result.confidence += 0.15;
            }
        }

        // Signal 3: Characteristic MOVZX ESI opcode-fetch + JMP [table + reg*8] pattern.
        // MOVZX: 0F B6 <ModRM fetching from [RSI]> → common VMProtect opcode fetch
        let vmp_fetch_count = count_pattern(binary, &[0x0F, 0xB6]);
        if vmp_fetch_count >= 3 {
            result.add_evidence(format!(
                "MOVZX opcode-fetch pattern appears {} times",
                vmp_fetch_count
            ));
            result.confidence += 0.15;
        }

        // Signal 4: dense indirect JMP cluster (handler table jump: FF 24 C5 xx xx xx xx)
        let jmp_table_count = count_pattern(binary, &[0xFF, 0x24]);
        if jmp_table_count >= 5 {
            result.add_evidence(format!(
                "JMP [table+reg] pattern appears {} times",
                jmp_table_count
            ));
            result.confidence += 0.10;
        }

        // Signal 5: CPUID present → VMProtect 3.x anti-VM detection.
        let cpuid_count = count_pattern(binary, &[0x0F, 0xA2]);
        if cpuid_count >= 2 {
            result.add_evidence(format!("CPUID x{} → likely VMProtect 3.x", cpuid_count));
            result.confidence += 0.15;
            result.protector = DetectedProtector::VMProtect3;
        }

        // Classify discovered handlers.
        let handlers = self.extract_handlers_near_jmp_table(binary, 0xFF24);
        for h in handlers {
            result.handlers.push(h);
        }

        result.confidence = result.confidence.min(1.0);
        if result.confidence > 0.0 {
            Some(result)
        } else {
            None
        }
    }

    // ── Themida / WinLicense ──────────────────────────────────────────────────

    /// Detect Themida / WinLicense handler patterns.
    ///
    /// Themida features very large handlers (50–300 bytes) with heavy XOR-based
    /// decryption loops at the start, API hooking patterns, and the characteristic
    /// `IsDebuggerPresent` anti-debugging import.
    pub fn detect_themida(&self, binary: &[u8]) -> Option<ProtectorDetectionResult> {
        let mut result = ProtectorDetectionResult::new(DetectedProtector::Themida);

        if contains_bytes(binary, b".themida") {
            result.add_evidence("Section '.themida' found");
            result.confidence += 0.55;
        }
        if contains_bytes(binary, b".winlicense") {
            result.add_evidence("Section '.winlicense' found");
            result.confidence += 0.55;
            result.protector = DetectedProtector::WinLicense;
        }
        for marker in [b"Themida".as_slice(), b"WinLicense", b"Oreans"] {
            if contains_bytes(binary, marker) {
                result.add_evidence(format!(
                    "Marker '{}' found",
                    std::str::from_utf8(marker).unwrap_or("?")
                ));
                result.confidence += 0.15;
            }
        }

        // High XOR density is characteristic of Themida's decryption loop.
        let xor_density = compute_xor_density(binary);
        if xor_density > 0.08 {
            result.add_evidence(format!(
                "High XOR instruction density: {:.1}%",
                xor_density * 100.0
            ));
            result.confidence += 0.10;
        }

        // IsDebuggerPresent hook pattern.
        if contains_bytes(binary, b"IsDebuggerPresent") {
            result.add_evidence("Import 'IsDebuggerPresent' (Themida anti-debug hook)");
            result.confidence += 0.10;
        }

        // CheckRemoteDebuggerPresent is also hooked by Themida.
        if contains_bytes(binary, b"CheckRemoteDebuggerPresent") {
            result.add_evidence("Import 'CheckRemoteDebuggerPresent' found");
            result.confidence += 0.05;
        }

        // RDTSC timing check pattern.
        let rdtsc_count = count_pattern(binary, &[0x0F, 0x31]);
        if rdtsc_count >= 3 {
            result.add_evidence(format!("RDTSC x{} (timing anti-debug)", rdtsc_count));
            result.confidence += 0.08;
        }

        // Themida often imports ntdll.DbgBreakPoint to neutralise it.
        if contains_bytes(binary, b"DbgBreakPoint") {
            result.add_evidence("'DbgBreakPoint' reference found (Themida hook target)");
            result.confidence += 0.07;
        }

        // Extract large-ish handler candidates.
        let handlers = self.extract_large_handlers(binary, 50, 300);
        result.handlers = handlers;

        result.confidence = result.confidence.min(1.0);
        if result.confidence > 0.0 {
            Some(result)
        } else {
            None
        }
    }

    // ── Code Virtualizer ──────────────────────────────────────────────────────

    /// Detect Code Virtualizer handler patterns.
    ///
    /// Code Virtualizer produces very compact handlers (10–60 bytes) with simple
    /// arithmetic and no encryption. The `.cv_DATA` / `.cv_CODE` sections are the
    /// primary indicator.
    pub fn detect_codevirtualizer(&self, binary: &[u8]) -> Option<ProtectorDetectionResult> {
        let mut result = ProtectorDetectionResult::new(DetectedProtector::CodeVirtualizer);

        if contains_bytes(binary, b".cv_DATA") {
            result.add_evidence("Section '.cv_DATA' found");
            result.confidence += 0.60;
        }
        if contains_bytes(binary, b".cv_CODE") {
            result.add_evidence("Section '.cv_CODE' found");
            result.confidence += 0.30;
        }
        for marker in [b"Code Virtualizer".as_slice(), b"cv_section", b"CV_SDK"] {
            if contains_bytes(binary, marker) {
                result.add_evidence(format!(
                    "Marker '{}' found",
                    std::str::from_utf8(marker).unwrap_or("?")
                ));
                result.confidence += 0.15;
            }
        }

        // Code Virtualizer: short handlers with indirect JMP at end.
        // Scan for runs of 10-60 bytes ending in FF E0-E7 or FF 24.
        let short_handlers = self.extract_handlers_near_jmp_table(binary, 0xFFE0);
        let short_count = short_handlers.len();
        if short_count >= 8 {
            result.add_evidence(format!(
                "Found {} short-handler+indirect-JMP sequences",
                short_count
            ));
            result.confidence += 0.15;
        }
        result.handlers = short_handlers;

        result.confidence = result.confidence.min(1.0);
        if result.confidence > 0.0 {
            Some(result)
        } else {
            None
        }
    }

    // ── Enigma Protector ──────────────────────────────────────────────────────

    /// Detect Enigma Protector handler patterns.
    ///
    /// Enigma Protector uses a mix of register-machine and stack-machine handlers.
    /// Its VM key distinguisher is a `MOV EAX, [EAX * 4 + handler_table]` dispatch
    /// pattern and the `.enigma1` / `.enigma2` section names.
    pub fn detect_enigma(&self, binary: &[u8]) -> Option<ProtectorDetectionResult> {
        let mut result = ProtectorDetectionResult::new(DetectedProtector::Enigma);

        for section in [b".enigma1".as_slice(), b".enigma2", b".enigma3"] {
            if contains_bytes(binary, section) {
                result.add_evidence(format!(
                    "Section '{}' found",
                    std::str::from_utf8(section).unwrap_or("?")
                ));
                result.confidence += 0.55;
            }
        }
        for marker in [b"Enigma Protector".as_slice(), b"Enigma", b"engima"] {
            if contains_bytes(binary, marker) {
                result.add_evidence(format!(
                    "String marker '{}' found",
                    std::str::from_utf8(marker).unwrap_or("?")
                ));
                result.confidence += 0.20;
            }
        }

        // Enigma uses SHL EAX, 2 / MOV EAX, [handler_base + EAX] pattern.
        // SHL EAX, 2 = C1 E0 02
        let shl_pattern = count_pattern(binary, &[0xC1, 0xE0, 0x02]);
        if shl_pattern >= 3 {
            result.add_evidence(format!(
                "SHL EAX,2 pattern x{} (scaled handler index)",
                shl_pattern
            ));
            result.confidence += 0.10;
        }

        // Enigma often uses GetSystemInfo / GetTickCount for anti-debug timing.
        for api in [b"GetSystemInfo".as_slice(), b"GetTickCount"] {
            if contains_bytes(binary, api) {
                result.add_evidence(format!(
                    "API '{}' referenced (Enigma timing check)",
                    std::str::from_utf8(api).unwrap_or("?")
                ));
                result.confidence += 0.05;
            }
        }

        // VirtualAlloc is used by Enigma for JIT-compiled handler stubs.
        if contains_bytes(binary, b"VirtualAlloc") {
            result.add_evidence("VirtualAlloc (Enigma JIT handler allocation)");
            result.confidence += 0.08;
        }

        let handlers = self.extract_small_handlers(binary, 15, 80);
        result.handlers = handlers;

        result.confidence = result.confidence.min(1.0);
        if result.confidence > 0.0 {
            Some(result)
        } else {
            None
        }
    }

    // ── Obsidium ──────────────────────────────────────────────────────────────

    /// Detect Obsidium handler patterns.
    ///
    /// Obsidium uses a two-stage VM: first a loader VM decrypts and verifies the
    /// payload, then a runtime VM executes the protected code. Key fingerprints are
    /// the `.obsidium` section names, heavy use of `PUSHFD/POPFD` for flag saving,
    /// and INT 3 anti-debug traps placed before/after handler prologues.
    pub fn detect_obsidium(&self, binary: &[u8]) -> Option<ProtectorDetectionResult> {
        let mut result = ProtectorDetectionResult::new(DetectedProtector::Obsidium);

        for section in [b".obsidiu".as_slice(), b"obsidium"] {
            if contains_bytes(binary, section) {
                result.add_evidence(format!(
                    "Section/marker '{}' found",
                    std::str::from_utf8(section).unwrap_or("?")
                ));
                result.confidence += 0.55;
            }
        }

        // PUSHFD (9C) / POPFD (9D) density — Obsidium saves/restores flags in every handler.
        let pushfd = count_single_byte(binary, 0x9C);
        let popfd = count_single_byte(binary, 0x9D);
        if pushfd >= 10 && popfd >= 10 {
            result.add_evidence(format!(
                "PUSHFD x{pushfd} / POPFD x{popfd} (Obsidium flag preservation)"
            ));
            result.confidence += 0.15;
        }

        // INT 3 (0xCC) traps placed as anti-debug.
        let int3_count = count_single_byte(binary, 0xCC);
        if int3_count >= 20 {
            result.add_evidence(format!("INT 3 x{int3_count} (Obsidium anti-debug traps)"));
            result.confidence += 0.10;
        }

        // Obsidium uses RDTSC + CPUID sequence for timing checks.
        let cpuid_count = count_pattern(binary, &[0x0F, 0xA2]);
        let rdtsc_count = count_pattern(binary, &[0x0F, 0x31]);
        if cpuid_count >= 2 && rdtsc_count >= 2 {
            result.add_evidence("CPUID+RDTSC combination (Obsidium anti-debug timing)");
            result.confidence += 0.10;
        }

        // Obsidium uses NtQueryInformationProcess as another anti-debug check.
        if contains_bytes(binary, b"NtQueryInformationProcess") {
            result.add_evidence("NtQueryInformationProcess (Obsidium anti-debug API)");
            result.confidence += 0.10;
        }

        // Import of SetUnhandledExceptionFilter (Obsidium exception-based anti-debug).
        if contains_bytes(binary, b"SetUnhandledExceptionFilter") {
            result.add_evidence("SetUnhandledExceptionFilter found");
            result.confidence += 0.05;
        }

        let handlers = self.extract_handlers_with_pushfd_popfd(binary);
        result.handlers = handlers;

        result.confidence = result.confidence.min(1.0);
        if result.confidence > 0.0 {
            Some(result)
        } else {
            None
        }
    }

    // ── Handler extraction helpers ─────────────────────────────────────────────

    /// Extract handler-like code blobs near indirect JMP instructions.
    ///
    /// `jmp_sig` is a 2-byte little-endian signature: e.g. `0xFF24` for `JMP [SIB]`
    /// or `0xFFE0` for `JMP EAX`.
    fn extract_handlers_near_jmp_table(
        &self,
        binary: &[u8],
        jmp_sig: u16,
    ) -> Vec<HandlerCandidate> {
        let lo = (jmp_sig & 0xFF) as u8;
        let hi = ((jmp_sig >> 8) & 0xFF) as u8;
        let mut candidates = Vec::new();
        let limit = binary.len().saturating_sub(2);
        let mut i = 0;
        while i < limit && candidates.len() < self.config.max_handlers {
            if binary[i] == lo && (binary[i + 1] == hi || (0xE0..=0xE7).contains(&binary[i + 1])) {
                // Back-track to find the PUSH at the handler start (up to 64 bytes).
                let start = i.saturating_sub(64);
                for j in (start..i).rev() {
                    if (0x50..=0x57).contains(&binary[j]) {
                        let body_end = (i + 2).min(binary.len());
                        let body = binary[j..body_end].to_vec();
                        let mut h = HandlerCandidate::new(j as u64, body);
                        classify_handler_body(&mut h);
                        candidates.push(h);
                        break;
                    }
                }
            }
            i += 1;
        }
        candidates
    }

    /// Extract handler-like code blobs based on size constraints.
    fn extract_large_handlers(
        &self,
        binary: &[u8],
        min_size: usize,
        max_size: usize,
    ) -> Vec<HandlerCandidate> {
        self.extract_by_size_and_jmp(binary, min_size, max_size)
    }

    /// Extract small handler blobs.
    fn extract_small_handlers(
        &self,
        binary: &[u8],
        min_size: usize,
        max_size: usize,
    ) -> Vec<HandlerCandidate> {
        self.extract_by_size_and_jmp(binary, min_size, max_size)
    }

    fn extract_by_size_and_jmp(
        &self,
        binary: &[u8],
        min_sz: usize,
        max_sz: usize,
    ) -> Vec<HandlerCandidate> {
        let mut candidates = Vec::new();
        let mut i = 0usize;
        let limit = binary.len().saturating_sub(2);
        while i < limit && candidates.len() < self.config.max_handlers {
            if (0x50..=0x57).contains(&binary[i]) {
                // Find the next indirect JMP within [min_sz, max_sz] bytes.
                let search_end = (i + max_sz).min(limit);
                for j in (i + min_sz)..search_end {
                    if binary[j] == 0xFF
                        && (j + 1 < binary.len())
                        && ((0xE0..=0xE7).contains(&binary[j + 1]) || binary[j + 1] == 0x24)
                    {
                        let body = binary[i..j + 2].to_vec();
                        let mut h = HandlerCandidate::new(i as u64, body);
                        classify_handler_body(&mut h);
                        if self.config.detect_junk {
                            h.has_junk_code = detect_junk_code(&h.body);
                        }
                        candidates.push(h);
                        break;
                    }
                }
            }
            i += 1;
        }
        candidates
    }

    /// Extract handlers identified by PUSHFD/POPFD bookends (Obsidium).
    fn extract_handlers_with_pushfd_popfd(&self, binary: &[u8]) -> Vec<HandlerCandidate> {
        let mut candidates = Vec::new();
        let mut i = 0usize;
        let limit = binary.len().saturating_sub(2);
        while i < limit && candidates.len() < self.config.max_handlers {
            if binary[i] == 0x9C {
                // Found PUSHFD; look for POPFD within 128 bytes.
                for j in (i + 4)..(i + 128).min(limit) {
                    if binary[j] == 0x9D {
                        let body = binary[i..j + 1].to_vec();
                        let mut h = HandlerCandidate::new(i as u64, body);
                        classify_handler_body(&mut h);
                        candidates.push(h);
                        break;
                    }
                }
            }
            i += 1;
        }
        candidates
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// HandlerSemanticClassifier — classify handler body → HandlerSemantic
// ─────────────────────────────────────────────────────────────────────────────

/// Classifies a raw handler body byte slice into a [`HandlerSemantic`].
#[derive(Debug, Clone, Default)]
pub struct HandlerSemanticClassifier;

impl HandlerSemanticClassifier {
    /// Create a new classifier.
    pub fn new() -> Self {
        Self
    }

    /// Classify `body` into a [`HandlerSemantic`] with a confidence score.
    pub fn classify(&self, body: &[u8]) -> (HandlerSemantic, f32) {
        if body.is_empty() {
            return (HandlerSemantic::Unknown, 0.0);
        }

        let features = BodyFeatures::extract(body);

        // VM exit: POPAD + RET or POPF + RET sequence
        if features.has_ret && features.popad_count > 0 {
            return (HandlerSemantic::VmExit, 0.85);
        }

        // VM enter: PUSHAD + JMP sequence
        if features.pushad_count > 0 && features.has_indirect_jmp {
            return (HandlerSemantic::VmEnter, 0.80);
        }

        // Stack operations
        if features.push_count >= 2 && features.pop_count == 0 && !features.has_alu {
            return (HandlerSemantic::Push, 0.75);
        }
        if features.pop_count >= 2 && features.push_count <= 1 && !features.has_alu {
            return (HandlerSemantic::Pop, 0.75);
        }

        // PUSHFD / POPFD
        if features.pushfd_count > 0 && features.pop_count == 0 {
            return (HandlerSemantic::PushFlags, 0.80);
        }
        if features.popfd_count > 0 && features.push_count == 0 {
            return (HandlerSemantic::PopFlags, 0.80);
        }

        // ADD
        if features.add_count >= 1 && !features.has_xor && !features.has_cmp {
            return (HandlerSemantic::Add, 0.70);
        }

        // SUB
        if features.sub_count >= 1 && !features.has_xor && !features.has_cmp {
            return (HandlerSemantic::Sub, 0.70);
        }

        // MUL
        if features.mul_count >= 1 {
            return (HandlerSemantic::Mul, 0.75);
        }

        // XOR
        if features.xor_count >= 1 && features.add_count == 0 && features.sub_count == 0 {
            return (HandlerSemantic::Xor, 0.70);
        }

        // AND
        if features.and_count >= 1 && features.xor_count == 0 {
            return (HandlerSemantic::And, 0.65);
        }

        // OR
        if features.or_count >= 1 && features.xor_count == 0 && features.and_count == 0 {
            return (HandlerSemantic::Or, 0.65);
        }

        // NOT
        if features.not_count >= 1 && !features.has_alu {
            return (HandlerSemantic::Not, 0.70);
        }

        // NEG
        if features.neg_count >= 1 {
            return (HandlerSemantic::Neg, 0.72);
        }

        // SHL / SHR
        if features.shl_count >= 1 && features.shr_count == 0 {
            return (HandlerSemantic::Shl, 0.70);
        }
        if features.shr_count >= 1 && features.shl_count == 0 {
            return (HandlerSemantic::Shr, 0.70);
        }

        // CMP → JCC
        if features.has_cmp && features.has_jcc {
            return (HandlerSemantic::Jcc, 0.75);
        }
        if features.has_cmp {
            return (HandlerSemantic::Cmp, 0.65);
        }

        // Unconditional JMP
        if features.has_indirect_jmp && !features.has_cmp && !features.has_ret {
            return (HandlerSemantic::Jmp, 0.60);
        }

        // CALL
        if features.has_call && !features.has_ret {
            return (HandlerSemantic::Call, 0.65);
        }

        // RET
        if features.has_ret && !features.has_indirect_jmp {
            return (HandlerSemantic::Ret, 0.70);
        }

        // MOV with memory operand → LOAD or STORE
        if features.mov_mem_count >= 2 {
            if features.push_count > features.pop_count {
                return (HandlerSemantic::Load, 0.60);
            } else {
                return (HandlerSemantic::Store, 0.60);
            }
        }

        // NOP-heavy
        if features.nop_count >= 3 && body.len() < 16 {
            return (HandlerSemantic::Nop, 0.55);
        }

        (HandlerSemantic::Unknown, 0.20)
    }
}

/// Features extracted from a handler body for semantic classification.
#[derive(Debug, Default)]
struct BodyFeatures {
    push_count: u32,
    pop_count: u32,
    pushad_count: u32,
    popad_count: u32,
    pushfd_count: u32,
    popfd_count: u32,
    add_count: u32,
    sub_count: u32,
    mul_count: u32,
    xor_count: u32,
    and_count: u32,
    or_count: u32,
    not_count: u32,
    neg_count: u32,
    shl_count: u32,
    shr_count: u32,
    mov_mem_count: u32,
    nop_count: u32,
    has_alu: bool,
    has_xor: bool,
    has_cmp: bool,
    has_jcc: bool,
    has_indirect_jmp: bool,
    has_call: bool,
    has_ret: bool,
}

impl BodyFeatures {
    fn extract(body: &[u8]) -> Self {
        let mut f = BodyFeatures::default();
        let mut i = 0;
        while i < body.len() {
            let b = body[i];
            match b {
                // PUSH reg
                0x50..=0x57 => f.push_count += 1,
                // POP reg
                0x58..=0x5F => f.pop_count += 1,
                // PUSHAD
                0x60 => f.pushad_count += 1,
                // POPAD
                0x61 => f.popad_count += 1,
                // PUSHFD
                0x9C => f.pushfd_count += 1,
                // POPFD
                0x9D => f.popfd_count += 1,
                // NOP
                0x90 => f.nop_count += 1,
                // ADD: 01/03 (reg), 05 (EAX+imm32)
                0x01 | 0x03 | 0x05 => {
                    f.add_count += 1;
                    f.has_alu = true;
                }
                // SUB: 29/2B/2D
                0x29 | 0x2B | 0x2D => {
                    f.sub_count += 1;
                    f.has_alu = true;
                }
                // AND: 21/23/25
                0x21 | 0x23 | 0x25 => {
                    f.and_count += 1;
                    f.has_alu = true;
                }
                // OR:  09/0B/0D
                0x09 | 0x0B | 0x0D => {
                    f.or_count += 1;
                    f.has_alu = true;
                }
                // XOR: 31/33/35
                0x31 | 0x33 | 0x35 => {
                    f.xor_count += 1;
                    f.has_alu = true;
                    f.has_xor = true;
                }
                // CMP: 39/3B/3D
                0x39 | 0x3B | 0x3D => f.has_cmp = true,
                // MOV (memory forms): 8B (reg,r/m), 89 (r/m, reg)
                0x8B | 0x89 => f.mov_mem_count += 1,
                // CALL rel32
                0xE8 => f.has_call = true,
                // Jcc short 70..7F
                0x70..=0x7F => f.has_jcc = true,
                // RET
                0xC2 | 0xC3 => f.has_ret = true,
                0x0F => {
                    if i + 1 < body.len() {
                        match body[i + 1] {
                            // IMUL: 0F AF
                            0xAF => {
                                f.mul_count += 1;
                                f.has_alu = true;
                            }
                            // Jcc near: 0F 80-8F
                            0x80..=0x8F => f.has_jcc = true,
                            // MUL/DIV via F7: handled below
                            _ => {}
                        }
                        i += 1; // consume second byte
                    }
                }
                0xF7 => {
                    if i + 1 < body.len() {
                        match body[i + 1] & 0x38 {
                            0x10 => {
                                f.not_count += 1;
                            } // NOT /2
                            0x18 => {
                                f.neg_count += 1;
                            } // NEG /3
                            0x20 | 0x28 => {
                                f.mul_count += 1;
                                f.has_alu = true;
                            } // MUL/IMUL /4-/5
                            _ => {}
                        }
                        i += 1;
                    }
                }
                0xC1 | 0xD1 | 0xD3 => {
                    // Shift/rotate: look at /reg field
                    if i + 1 < body.len() {
                        match (body[i + 1] >> 3) & 7 {
                            4 => f.shl_count += 1,
                            5 => f.shr_count += 1,
                            _ => {}
                        }
                        i += 1;
                    }
                }
                0xFF => {
                    if i + 1 < body.len() {
                        let modrm = body[i + 1];
                        if (0xE0..=0xE7).contains(&modrm) || modrm == 0x24 {
                            f.has_indirect_jmp = true;
                        }
                        if (0xD0..=0xD7).contains(&modrm) {
                            f.has_call = true;
                        }
                        i += 1;
                    }
                }
                _ => {}
            }
            i += 1;
        }
        f
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Private helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Classify a mutable handler candidate in-place.
fn classify_handler_body(h: &mut HandlerCandidate) {
    let classifier = HandlerSemanticClassifier::new();
    let (semantic, confidence) = classifier.classify(&h.body);
    h.semantic = semantic;
    h.confidence = confidence;

    // Set rough stack counts.
    match semantic {
        HandlerSemantic::Push => {
            h.stack_pop_count = 0;
            h.stack_push_count = 1;
        }
        HandlerSemantic::Pop => {
            h.stack_pop_count = 1;
            h.stack_push_count = 0;
        }
        HandlerSemantic::Add
        | HandlerSemantic::Sub
        | HandlerSemantic::And
        | HandlerSemantic::Or
        | HandlerSemantic::Xor => {
            h.stack_pop_count = 2;
            h.stack_push_count = 1;
        }
        HandlerSemantic::Not | HandlerSemantic::Neg => {
            h.stack_pop_count = 1;
            h.stack_push_count = 1;
        }
        HandlerSemantic::Jmp | HandlerSemantic::Call => {
            h.stack_pop_count = 1;
            h.stack_push_count = 0;
        }
        HandlerSemantic::Ret => {
            h.stack_pop_count = 1;
            h.stack_push_count = 0;
        }
        _ => {}
    }

    h.estimated_size = h.body.len();
    h.add_evidence(format!(
        "classified as {} (confidence {:.0}%)",
        semantic.mnemonic(),
        confidence * 100.0
    ));
}

/// Returns `true` if `binary` contains `needle` as a sub-slice.
fn contains_bytes(binary: &[u8], needle: &[u8]) -> bool {
    binary.windows(needle.len()).any(|w| w == needle)
}

/// Count non-overlapping occurrences of a 2-byte pattern.
fn count_pattern(binary: &[u8], pattern: &[u8]) -> usize {
    if pattern.len() > binary.len() {
        return 0;
    }
    let mut count = 0;
    let mut i = 0;
    while i + pattern.len() <= binary.len() {
        if binary[i..i + pattern.len()] == *pattern {
            count += 1;
            i += pattern.len();
        } else {
            i += 1;
        }
    }
    count
}

/// Count occurrences of a single byte value.
fn count_single_byte(binary: &[u8], byte: u8) -> usize {
    binary.iter().filter(|&&b| b == byte).count()
}

/// Compute the ratio of XOR instruction bytes in the binary (as a density metric).
fn compute_xor_density(binary: &[u8]) -> f64 {
    if binary.is_empty() {
        return 0.0;
    }
    let xor_count = binary
        .iter()
        .filter(|&&b| b == 0x31 || b == 0x33 || b == 0x35)
        .count();
    xor_count as f64 / binary.len() as f64
}

/// Detect junk code in a handler body (repeated NOPs, useless XOR self, etc.)
fn detect_junk_code(body: &[u8]) -> bool {
    let nop_count = count_single_byte(body, 0x90);
    if nop_count > 4 {
        return true;
    }
    // XOR reg, reg (e.g. 31 C0 = XOR EAX, EAX) used as junk
    body.windows(2)
        .any(|w| w[0] == 0x31 && (w[1] & 0xC7 == 0xC0))
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_handler_semantic_predicates() {
        assert!(HandlerSemantic::Jmp.is_control_flow());
        assert!(HandlerSemantic::VmExit.is_control_flow());
        assert!(!HandlerSemantic::Add.is_control_flow());
        assert!(HandlerSemantic::Add.is_binary_alu());
        assert!(!HandlerSemantic::Push.is_binary_alu());
    }

    #[test]
    fn test_handler_semantic_mnemonic() {
        assert_eq!(HandlerSemantic::Add.mnemonic(), "ADD");
        assert_eq!(HandlerSemantic::VmExit.mnemonic(), "VM_EXIT");
        assert_eq!(HandlerSemantic::Unknown.mnemonic(), "???");
    }

    #[test]
    fn test_body_classifier_push() {
        // PUSH EAX, PUSH ECX, JMP [EAX]
        let body = vec![0x50, 0x51, 0xFF, 0xE0];
        let classifier = HandlerSemanticClassifier::new();
        let (sem, conf) = classifier.classify(&body);
        // push_count=2, pop_count=0 → Push
        assert_eq!(sem, HandlerSemantic::Push);
        assert!(conf > 0.5);
    }

    #[test]
    fn test_body_classifier_add() {
        // PUSH EAX, PUSH ECX, ADD EAX, ECX (03 C1), POP EAX, JMP [EAX]
        let body = vec![0x50, 0x51, 0x03, 0xC1, 0x58, 0xFF, 0xE0];
        let classifier = HandlerSemanticClassifier::new();
        let (sem, _) = classifier.classify(&body);
        assert_eq!(sem, HandlerSemantic::Add);
    }

    #[test]
    fn test_body_classifier_ret() {
        let body = vec![0x5A, 0xC3]; // POP EDX, RET
        let classifier = HandlerSemanticClassifier::new();
        let (sem, _) = classifier.classify(&body);
        assert_eq!(sem, HandlerSemantic::Ret);
    }

    #[test]
    fn test_body_classifier_empty() {
        let classifier = HandlerSemanticClassifier::new();
        let (sem, conf) = classifier.classify(&[]);
        assert_eq!(sem, HandlerSemantic::Unknown);
        assert_eq!(conf, 0.0);
    }

    #[test]
    fn test_handler_candidate_stack_delta() {
        let mut h = HandlerCandidate::new(0x1000, vec![]);
        h.stack_push_count = 2;
        h.stack_pop_count = 1;
        assert_eq!(h.stack_delta(), 1);
    }

    #[test]
    fn test_detect_vmprotect_vmp_section() {
        let mut binary = vec![0u8; 64];
        binary.extend_from_slice(b".vmp0");
        let analyzer = VmHandlerAnalyzer::new();
        let result = analyzer.detect_vmprotect(&binary).unwrap();
        assert!(result.confidence >= 0.40);
        assert!(result.evidence.iter().any(|e| e.contains(".vmp0")));
    }

    #[test]
    fn test_detect_vmprotect_cpuid_upgrades_to_v3() {
        let mut binary = vec![0u8; 64];
        binary.extend_from_slice(b".vmp0");
        // CPUID twice
        binary.extend_from_slice(&[0x0F, 0xA2, 0x0F, 0xA2]);
        let analyzer = VmHandlerAnalyzer::new();
        let result = analyzer.detect_vmprotect(&binary).unwrap();
        assert_eq!(result.protector, DetectedProtector::VMProtect3);
    }

    #[test]
    fn test_detect_themida_section() {
        let mut binary = vec![0u8; 64];
        binary.extend_from_slice(b".themida");
        let analyzer = VmHandlerAnalyzer::new();
        let result = analyzer.detect_themida(&binary).unwrap();
        assert!(result.confidence >= 0.55);
    }

    #[test]
    fn test_detect_winlicense_section() {
        let mut binary = vec![0u8; 64];
        binary.extend_from_slice(b".winlicense");
        let analyzer = VmHandlerAnalyzer::new();
        let result = analyzer.detect_themida(&binary).unwrap();
        assert_eq!(result.protector, DetectedProtector::WinLicense);
    }

    #[test]
    fn test_detect_codevirtualizer_section() {
        let mut binary = vec![0u8; 64];
        binary.extend_from_slice(b".cv_DATA");
        let analyzer = VmHandlerAnalyzer::new();
        let result = analyzer.detect_codevirtualizer(&binary).unwrap();
        assert!(result.confidence >= 0.60);
    }

    #[test]
    fn test_detect_enigma_section() {
        let mut binary = vec![0u8; 64];
        binary.extend_from_slice(b".enigma1");
        let analyzer = VmHandlerAnalyzer::new();
        let result = analyzer.detect_enigma(&binary).unwrap();
        assert!(result.confidence >= 0.55);
    }

    #[test]
    fn test_detect_obsidium_section() {
        let mut binary = vec![0u8; 64];
        binary.extend_from_slice(b".obsidiu");
        let analyzer = VmHandlerAnalyzer::new();
        let result = analyzer.detect_obsidium(&binary).unwrap();
        assert!(result.confidence >= 0.55);
    }

    #[test]
    fn test_analyze_empty_binary() {
        let analyzer = VmHandlerAnalyzer::new();
        assert!(analyzer.analyze(&[]).is_err());
    }

    #[test]
    fn test_analyze_returns_sorted() {
        let mut binary = vec![0u8; 64];
        binary.extend_from_slice(b".vmp0.vmp1");
        binary.extend_from_slice(b"VMProtect");
        binary.extend_from_slice(&[0x0F, 0xB6, 0x0F, 0xB6, 0x0F, 0xB6]);
        let analyzer = VmHandlerAnalyzer::new();
        let results = analyzer.analyze(&binary).unwrap();
        for pair in results.windows(2) {
            assert!(
                pair[0].confidence >= pair[1].confidence,
                "results must be sorted descending"
            );
        }
    }

    #[test]
    fn test_contains_bytes() {
        assert!(contains_bytes(b"hello world", b"world"));
        assert!(!contains_bytes(b"hello", b"world"));
    }

    #[test]
    fn test_count_pattern() {
        let data = &[0x0F, 0xB6, 0xFF, 0x0F, 0xB6];
        assert_eq!(count_pattern(data, &[0x0F, 0xB6]), 2);
    }

    #[test]
    fn test_detect_junk_code_nop_sled() {
        let body = vec![0x90u8; 8]; // NOP sled
        assert!(detect_junk_code(&body));
    }

    #[test]
    fn test_detect_junk_code_xor_self() {
        let body = vec![0x31, 0xC0]; // XOR EAX, EAX
        assert!(detect_junk_code(&body));
    }

    #[test]
    fn test_detected_protector_name() {
        assert_eq!(DetectedProtector::VMProtect2.name(), "VMProtect 2.x");
        assert_eq!(
            DetectedProtector::CodeVirtualizer.name(),
            "Code Virtualizer"
        );
        assert!(DetectedProtector::VMProtect2.is_stack_based());
        assert!(!DetectedProtector::Enigma.is_stack_based());
    }

    #[test]
    fn test_protector_detection_result_classified_count() {
        let mut result = ProtectorDetectionResult::new(DetectedProtector::VMProtect2);
        let mut h1 = HandlerCandidate::new(0x1000, vec![]);
        h1.semantic = HandlerSemantic::Add;
        let mut h2 = HandlerCandidate::new(0x1100, vec![]);
        h2.semantic = HandlerSemantic::Unknown;
        result.handlers.push(h1);
        result.handlers.push(h2);
        assert_eq!(result.classified_count(), 1);
    }
}
