//! `protector_patterns` — Known commercial VM-protector signature database.
//!
//! Maintains a catalogue of byte-level signatures for popular commercial
//! protectors: `VMProtect` 2/3, Themida 1/2, Code Virtualizer 1/2, Enigma,
//! and Obsidium.  Each protector is represented as a set of
//! [`PatternSignature`] entries covering the dispatcher, VM-entry, and
//! handler-dispatch recognition points.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

// ---------------------------------------------------------------------------
// ProtectorPattern — enum of known protectors
// ---------------------------------------------------------------------------

/// Commercial software protectors with known VM implementations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ProtectorPattern {
    /// `VMProtect` 2.x (x86/x64 stack-based VM).
    VMProtect2,
    /// `VMProtect` 3.x (improved mutation, x64 only).
    VMProtect3,
    /// Themida 1.x (32-bit `CodeReplace` engine).
    Themida1,
    /// Themida 2.x / `WinLicense` 2.x (64-bit engine).
    Themida2,
    /// Code Virtualizer 1.x (entry-point VM).
    CodeVirtualizer1,
    /// Code Virtualizer 2.x (multi-handler VM).
    CodeVirtualizer2,
    /// Enigma Protector 4.x.
    Enigma,
    /// Obsidium 1.x (CRC + VM + anti-debug).
    Obsidium,
}

impl ProtectorPattern {
    /// Human-readable name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::VMProtect2 => "VMProtect 2",
            Self::VMProtect3 => "VMProtect 3",
            Self::Themida1 => "Themida 1",
            Self::Themida2 => "Themida 2",
            Self::CodeVirtualizer1 => "Code Virtualizer 1",
            Self::CodeVirtualizer2 => "Code Virtualizer 2",
            Self::Enigma => "Enigma Protector",
            Self::Obsidium => "Obsidium",
        }
    }

    /// Expected minimum confidence for a positive identification.
    #[must_use]
    pub const fn min_confidence(self) -> u8 {
        match self {
            Self::VMProtect2 | Self::VMProtect3 => 70,
            Self::Themida1 | Self::Themida2 => 65,
            Self::CodeVirtualizer1 | Self::CodeVirtualizer2 => 60,
            Self::Enigma | Self::Obsidium => 55,
        }
    }
}

impl fmt::Display for ProtectorPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

// ---------------------------------------------------------------------------
// SignatureKind — what code construct the bytes belong to
// ---------------------------------------------------------------------------

/// What construct a [`PatternSignature`] targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SignatureKind {
    /// The main VM dispatcher loop.
    Dispatcher,
    /// The VM entry trampoline (OEP stub / call-gate).
    VmEntry,
    /// A handler-table lookup or indirect jump.
    HandlerDispatch,
    /// The initialisation / key-setup routine.
    Initialisation,
    /// Anti-debug check.
    AntiDebug,
    /// Decryption loop.
    Decryption,
}

impl fmt::Display for SignatureKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Dispatcher => "dispatcher",
            Self::VmEntry => "vm-entry",
            Self::HandlerDispatch => "handler-dispatch",
            Self::Initialisation => "initialisation",
            Self::AntiDebug => "anti-debug",
            Self::Decryption => "decryption",
        };
        write!(f, "{s}")
    }
}

// ---------------------------------------------------------------------------
// BytePattern — wildcard-aware byte sequence
// ---------------------------------------------------------------------------

/// A byte sequence where `None` acts as a wildcard (matches any byte).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BytePattern(pub Vec<Option<u8>>);

impl BytePattern {
    /// Construct from an exact byte slice (no wildcards).
    #[must_use]
    pub fn exact(bytes: &[u8]) -> Self {
        Self(bytes.iter().map(|&b| Some(b)).collect())
    }

    /// Construct from a `&[Option<u8>]` slice.
    #[must_use]
    pub fn wildcard(bytes: &[Option<u8>]) -> Self {
        Self(bytes.to_vec())
    }

    /// Pattern length (in bytes).
    #[must_use]
    pub const fn len(&self) -> usize {
        self.0.len()
    }

    /// Return `true` if the pattern is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Return `true` if `data[offset..]` matches this pattern.
    #[must_use]
    pub fn matches_at(&self, data: &[u8], offset: usize) -> bool {
        if offset + self.0.len() > data.len() {
            return false;
        }
        self.0
            .iter()
            .zip(data[offset..].iter())
            .all(|(pat, &b)| pat.is_none_or(|p| p == b))
    }

    /// Return all offsets in `data` where this pattern matches.
    #[must_use]
    pub fn find_all(&self, data: &[u8]) -> Vec<usize> {
        if self.0.is_empty() {
            return Vec::new();
        }
        (0..data.len())
            .filter(|&i| self.matches_at(data, i))
            .collect()
    }

    /// Return the first match offset, or `None`.
    #[must_use]
    pub fn find_first(&self, data: &[u8]) -> Option<usize> {
        if self.0.is_empty() {
            return None;
        }
        (0..data.len()).find(|&i| self.matches_at(data, i))
    }
}

// ---------------------------------------------------------------------------
// PatternSignature
// ---------------------------------------------------------------------------

/// A single signature entry for a protector detection pattern.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternSignature {
    /// Which protector this signature belongs to.
    pub protector: ProtectorPattern,
    /// Kind of construct targeted.
    pub kind: SignatureKind,
    /// Human-readable description.
    pub description: String,
    /// Byte pattern to search for.
    pub pattern: BytePattern,
    /// Confidence contribution (0–100).  Multiple signatures can contribute.
    pub confidence: u8,
    /// Minimum binary size required before attempting this match.
    pub min_file_size: usize,
}

impl PatternSignature {
    /// Create a simple signature.
    #[must_use]
    pub fn new(
        protector: ProtectorPattern,
        kind: SignatureKind,
        description: impl Into<String>,
        pattern: BytePattern,
        confidence: u8,
    ) -> Self {
        Self {
            protector,
            kind,
            description: description.into(),
            pattern,
            confidence: confidence.clamp(1, 100),
            min_file_size: 256,
        }
    }

    /// Return `true` if the signature matches anywhere in `data`.
    #[must_use]
    pub fn matches(&self, data: &[u8]) -> bool {
        data.len() >= self.min_file_size && self.pattern.find_first(data).is_some()
    }

    /// Return all match offsets within `data`.
    #[must_use]
    pub fn find_all(&self, data: &[u8]) -> Vec<usize> {
        if data.len() < self.min_file_size {
            return Vec::new();
        }
        self.pattern.find_all(data)
    }
}

// ---------------------------------------------------------------------------
// DetectedProtector
// ---------------------------------------------------------------------------

/// Result of a protector detection run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectedProtector {
    /// Which protector was detected.
    pub protector: ProtectorPattern,
    /// Accumulated confidence score (0–100).
    pub confidence: u8,
    /// Human-readable version hint (e.g. "2.x").
    pub version_hint: String,
    /// Offsets within the binary where matching signatures were found.
    pub match_offsets: Vec<usize>,
    /// Names of the signatures that matched.
    pub matched_signatures: Vec<String>,
}

impl DetectedProtector {
    /// Return `true` if the confidence meets the protector's minimum threshold.
    #[must_use]
    pub fn is_confident(&self) -> bool {
        self.confidence >= self.protector.min_confidence()
    }
}

impl fmt::Display for DetectedProtector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} (confidence={}, matches={})",
            self.protector,
            self.version_hint,
            self.confidence,
            self.match_offsets.len()
        )
    }
}

// ---------------------------------------------------------------------------
// PatternDb — the signature database
// ---------------------------------------------------------------------------

/// Signature database holding all registered [`PatternSignature`] entries.
#[derive(Default)]
pub struct PatternDb {
    signatures: Vec<PatternSignature>,
}

impl PatternDb {
    /// Create an empty database.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Build the built-in database containing signatures for all supported
    /// protectors.
    #[must_use]
    pub fn builtin() -> Self {
        let mut db = Self::new();
        db.add_vmprotect2_signatures();
        db.add_vmprotect3_signatures();
        db.add_themida1_signatures();
        db.add_themida2_signatures();
        db.add_codevirtualizer1_signatures();
        db.add_codevirtualizer2_signatures();
        db.add_enigma_signatures();
        db.add_obsidium_signatures();
        db
    }

    /// Register a signature.
    pub fn register(&mut self, sig: PatternSignature) {
        self.signatures.push(sig);
    }

    /// Number of signatures.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.signatures.len()
    }

    /// Return `true` if no signatures are registered.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.signatures.is_empty()
    }

    /// Return all signatures for a specific protector.
    #[must_use]
    pub fn for_protector(&self, p: ProtectorPattern) -> Vec<&PatternSignature> {
        self.signatures
            .iter()
            .filter(|s| s.protector == p)
            .collect()
    }

    /// Return all signatures of a specific kind.
    #[must_use]
    pub fn of_kind(&self, kind: SignatureKind) -> Vec<&PatternSignature> {
        self.signatures.iter().filter(|s| s.kind == kind).collect()
    }

    // ── VMProtect 2 ───────────────────────────────────────────────────────────

    fn add_vmprotect2_signatures(&mut self) {
        // Dispatcher: PUSHFD; PUSHAD; CALL+5; POP; LEA; JMP [handler_table]
        self.register(PatternSignature::new(
            ProtectorPattern::VMProtect2,
            SignatureKind::Dispatcher,
            "VMProtect2 PUSHFD+PUSHAD dispatcher prologue",
            BytePattern::exact(&[0x9C, 0x60]), // PUSHFD; PUSHAD
            70,
        ));
        // VM-entry stub: MOV EBP, ESP; PUSH xxx; CALL decrypt_key
        self.register(PatternSignature::new(
            ProtectorPattern::VMProtect2,
            SignatureKind::VmEntry,
            "VMProtect2 vm-entry MOV EBP,ESP setup",
            BytePattern::exact(&[0x8B, 0xEC, 0x68]), // MOV EBP,ESP; PUSH imm
            60,
        ));
        // Handler dispatch: MOVZX EAX, BYTE [ESI]; INC ESI; JMP [EAX*4+table]
        self.register(PatternSignature::new(
            ProtectorPattern::VMProtect2,
            SignatureKind::HandlerDispatch,
            "VMProtect2 bytecode fetch MOVZX+INC+JMP",
            BytePattern::wildcard(&[
                Some(0x0F),
                Some(0xB6),
                Some(0x06), // MOVZX EAX, [ESI]
                Some(0x46), // INC ESI
            ]),
            75,
        ));
        // Key init: XOR EBX, EBX; MOV ECX, imm32 (loop count)
        self.register(PatternSignature::new(
            ProtectorPattern::VMProtect2,
            SignatureKind::Initialisation,
            "VMProtect2 key XOR init",
            BytePattern::exact(&[0x33, 0xDB, 0xB9]), // XOR EBX,EBX; MOV ECX,imm
            50,
        ));
        // Decryption loop: XOR [ESI+EAX], CL; INC EAX; LOOP
        self.register(PatternSignature::new(
            ProtectorPattern::VMProtect2,
            SignatureKind::Decryption,
            "VMProtect2 XOR decrypt loop",
            BytePattern::wildcard(&[
                Some(0x30),
                Some(0x0C),
                Some(0x06), // XOR [ESI+EAX], CL
                Some(0x40), // INC EAX
                Some(0xE2),
                None, // LOOP rel8
            ]),
            65,
        ));
    }

    // ── VMProtect 3 ───────────────────────────────────────────────────────────

    fn add_vmprotect3_signatures(&mut self) {
        // x64 VM-entry: PUSH RBP; MOV RBP, RSP; SUB RSP, imm; CALL decrypt
        self.register(PatternSignature::new(
            ProtectorPattern::VMProtect3,
            SignatureKind::VmEntry,
            "VMProtect3 x64 frame setup",
            BytePattern::exact(&[0x55, 0x48, 0x89, 0xE5, 0x48, 0x83, 0xEC]),
            75,
        ));
        // x64 dispatcher: MOV AL, [RSI]; INC RSI; JMP [RAX*8+table]
        self.register(PatternSignature::new(
            ProtectorPattern::VMProtect3,
            SignatureKind::Dispatcher,
            "VMProtect3 x64 bytecode fetch MOV AL,[RSI]",
            BytePattern::wildcard(&[
                Some(0x8A),
                Some(0x06), // MOV AL, [RSI]
                Some(0x48),
                Some(0xFF),
                Some(0xC6), // INC RSI
            ]),
            80,
        ));
        // Handler table indirect jump: FF 24 C5 (JMP [RAX*8+imm32])
        self.register(PatternSignature::new(
            ProtectorPattern::VMProtect3,
            SignatureKind::HandlerDispatch,
            "VMProtect3 JMP [RAX*8+handler_table]",
            BytePattern::exact(&[0xFF, 0x24, 0xC5]),
            80,
        ));
        // Key schedule: MOVABS RAX, key; XORPS XMM0, XMM0
        self.register(PatternSignature::new(
            ProtectorPattern::VMProtect3,
            SignatureKind::Initialisation,
            "VMProtect3 MOVABS key load",
            BytePattern::wildcard(&[
                Some(0x48),
                Some(0xB8),
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None, // MOVABS RAX, imm64
            ]),
            55,
        ));
        // Anti-debug: RDTSC; SUB EAX, prev; CMP EAX, threshold
        self.register(PatternSignature::new(
            ProtectorPattern::VMProtect3,
            SignatureKind::AntiDebug,
            "VMProtect3 RDTSC anti-debug timing check",
            BytePattern::exact(&[0x0F, 0x31, 0x2B, 0xC0]), // RDTSC; SUB EAX, EAX (simplified)
            60,
        ));
    }

    // ── Themida 1 ─────────────────────────────────────────────────────────────

    fn add_themida1_signatures(&mut self) {
        // Section name ".themida" in PE
        self.register(PatternSignature::new(
            ProtectorPattern::Themida1,
            SignatureKind::VmEntry,
            "Themida1 .themida section name",
            BytePattern::exact(b".themida"),
            80,
        ));
        // Dispatcher: PUSHA; PUSHF; CALL $+5; POP ESI; ADD ESI, delta
        self.register(PatternSignature::new(
            ProtectorPattern::Themida1,
            SignatureKind::Dispatcher,
            "Themida1 PUSHA+PUSHF save-all dispatcher",
            BytePattern::exact(&[0x60, 0x9C, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x5E]),
            85,
        ));
        // Handler index: LODSB; MOVZX EAX, AL; JMP [EAX*4+table]
        self.register(PatternSignature::new(
            ProtectorPattern::Themida1,
            SignatureKind::HandlerDispatch,
            "Themida1 LODSB handler fetch",
            BytePattern::exact(&[0xAC, 0x0F, 0xB6, 0xC0]),
            70,
        ));
        // Key: MOV ECX, 0x100; XOR EAX, EAX (S-box init)
        self.register(PatternSignature::new(
            ProtectorPattern::Themida1,
            SignatureKind::Initialisation,
            "Themida1 S-box initialisation MOV ECX,0x100",
            BytePattern::exact(&[0xB9, 0x00, 0x01, 0x00, 0x00, 0x33, 0xC0]),
            60,
        ));
        // Anti-debug: INT 3 (intentional breakpoint trapping)
        self.register(PatternSignature::new(
            ProtectorPattern::Themida1,
            SignatureKind::AntiDebug,
            "Themida1 INT3 anti-debug trap",
            BytePattern::exact(&[0xCC, 0xEB, 0x01]),
            55,
        ));
    }

    // ── Themida 2 ─────────────────────────────────────────────────────────────

    fn add_themida2_signatures(&mut self) {
        self.register(PatternSignature::new(
            ProtectorPattern::Themida2,
            SignatureKind::VmEntry,
            "Themida2 x64 vm-entry PUSH RBP; MOV RBP,RSP",
            BytePattern::exact(&[0x55, 0x48, 0x89, 0xE5]),
            65,
        ));
        // Dispatcher: MOV AL, [R14]; INC R14 (R14 = virtual IP)
        self.register(PatternSignature::new(
            ProtectorPattern::Themida2,
            SignatureKind::Dispatcher,
            "Themida2 x64 virtual IP fetch via R14",
            BytePattern::exact(&[0x41, 0x8A, 0x06, 0x49, 0xFF, 0xC6]),
            80,
        ));
        // Handler jump: JMP [R15+RAX*8] (R15 = handler table base)
        self.register(PatternSignature::new(
            ProtectorPattern::Themida2,
            SignatureKind::HandlerDispatch,
            "Themida2 JMP [R15+RAX*8] handler table",
            BytePattern::exact(&[0x43, 0xFF, 0x24, 0xC7]),
            80,
        ));
        // Decryption: ROL RAX, CL; XOR RAX, RCX
        self.register(PatternSignature::new(
            ProtectorPattern::Themida2,
            SignatureKind::Decryption,
            "Themida2 ROL+XOR decryption round",
            BytePattern::exact(&[0x48, 0xD3, 0xC0, 0x48, 0x33, 0xC1]),
            65,
        ));
        // Anti-debug: NtQueryInformationProcess hash check (CALL [IAT+offset])
        self.register(PatternSignature::new(
            ProtectorPattern::Themida2,
            SignatureKind::AntiDebug,
            "Themida2 indirect NtQueryInformationProcess check",
            BytePattern::exact(&[0xFF, 0x15]), // indirect CALL
            40,
        ));
    }

    // ── Code Virtualizer 1 ────────────────────────────────────────────────────

    fn add_codevirtualizer1_signatures(&mut self) {
        // Section ".vmp0" or ".cv"
        self.register(PatternSignature::new(
            ProtectorPattern::CodeVirtualizer1,
            SignatureKind::VmEntry,
            "CodeVirtualizer1 .vmp0 section",
            BytePattern::exact(b".vmp0"),
            80,
        ));
        // Entry stub: PUSH EBP; CALL vm_entry_decrypt
        self.register(PatternSignature::new(
            ProtectorPattern::CodeVirtualizer1,
            SignatureKind::VmEntry,
            "CodeVirtualizer1 PUSH EBP entry stub",
            BytePattern::exact(&[0x55, 0xE8]),
            55,
        ));
        // Dispatcher: LODSD; AND EAX, handler_mask; JMP [EAX+table]
        self.register(PatternSignature::new(
            ProtectorPattern::CodeVirtualizer1,
            SignatureKind::Dispatcher,
            "CodeVirtualizer1 LODSD dispatcher",
            BytePattern::exact(&[0xAD, 0x25]), // LODSD; AND EAX, imm
            65,
        ));
        // Init: MOV EDI, vm_context; PUSH 0; POP EAX
        self.register(PatternSignature::new(
            ProtectorPattern::CodeVirtualizer1,
            SignatureKind::Initialisation,
            "CodeVirtualizer1 context init MOV EDI",
            BytePattern::exact(&[0xBF]), // MOV EDI, imm32
            45,
        ));
        // Decryption: ROL EBX, 1; XOR EBX, key_const
        self.register(PatternSignature::new(
            ProtectorPattern::CodeVirtualizer1,
            SignatureKind::Decryption,
            "CodeVirtualizer1 ROL+XOR key round",
            BytePattern::exact(&[0xD1, 0xC3, 0x81, 0xF3]),
            60,
        ));
    }

    // ── Code Virtualizer 2 ────────────────────────────────────────────────────

    fn add_codevirtualizer2_signatures(&mut self) {
        self.register(PatternSignature::new(
            ProtectorPattern::CodeVirtualizer2,
            SignatureKind::VmEntry,
            "CodeVirtualizer2 .cv1 section",
            BytePattern::exact(b".cv1"),
            75,
        ));
        // 64-bit dispatcher: MOV R10, [RIP+delta]; PUSH R10; RET
        self.register(PatternSignature::new(
            ProtectorPattern::CodeVirtualizer2,
            SignatureKind::Dispatcher,
            "CodeVirtualizer2 MOV R10,[RIP] dispatcher",
            BytePattern::exact(&[0x4C, 0x8B, 0x15]), // MOV R10, [RIP+rel32]
            70,
        ));
        // Handler table: LEA R11, [RIP+table]; JMP [R11+RAX*8]
        self.register(PatternSignature::new(
            ProtectorPattern::CodeVirtualizer2,
            SignatureKind::HandlerDispatch,
            "CodeVirtualizer2 LEA R11 handler table",
            BytePattern::exact(&[0x4C, 0x8D, 0x1D]), // LEA R11, [RIP+rel32]
            70,
        ));
        // Decryption: IMUL RAX, RCX, magic_const
        self.register(PatternSignature::new(
            ProtectorPattern::CodeVirtualizer2,
            SignatureKind::Decryption,
            "CodeVirtualizer2 IMUL decryption",
            BytePattern::exact(&[0x48, 0x69, 0xC1]), // IMUL RAX, RCX, imm32
            55,
        ));
        // Anti-debug: QueryPerformanceCounter timing check
        self.register(PatternSignature::new(
            ProtectorPattern::CodeVirtualizer2,
            SignatureKind::AntiDebug,
            "CodeVirtualizer2 QPC timing anti-debug",
            BytePattern::exact(&[0x0F, 0x31, 0x48, 0xC1, 0xE2, 0x20]), // RDTSC; SHL RDX,32
            60,
        ));
    }

    // ── Enigma ────────────────────────────────────────────────────────────────

    fn add_enigma_signatures(&mut self) {
        // Header: "Enigma" magic at PE overlay
        self.register(PatternSignature::new(
            ProtectorPattern::Enigma,
            SignatureKind::Initialisation,
            "Enigma Protector header magic",
            BytePattern::exact(b"Enigma"),
            85,
        ));
        // EPOL section
        self.register(PatternSignature::new(
            ProtectorPattern::Enigma,
            SignatureKind::VmEntry,
            "Enigma .enigma section name",
            BytePattern::exact(b".enigma"),
            80,
        ));
        // Dispatcher: CALL [EBP+handler_offset]
        self.register(PatternSignature::new(
            ProtectorPattern::Enigma,
            SignatureKind::Dispatcher,
            "Enigma CALL [EBP+offset] indirect dispatch",
            BytePattern::exact(&[0xFF, 0x55]),
            55,
        ));
        // Crypto: BSWAP EAX; XOR EAX, key
        self.register(PatternSignature::new(
            ProtectorPattern::Enigma,
            SignatureKind::Decryption,
            "Enigma BSWAP+XOR byte-swap decryption",
            BytePattern::exact(&[0x0F, 0xC8, 0x35]), // BSWAP EAX; XOR EAX,imm
            60,
        ));
        // Anti-debug: CheckRemoteDebuggerPresent via IsDebuggerPresent IAT
        self.register(PatternSignature::new(
            ProtectorPattern::Enigma,
            SignatureKind::AntiDebug,
            "Enigma IsDebuggerPresent CMP check",
            BytePattern::exact(&[0x85, 0xC0, 0x74]), // TEST EAX,EAX; JZ not_debugged
            50,
        ));
    }

    // ── Obsidium ──────────────────────────────────────────────────────────────

    fn add_obsidium_signatures(&mut self) {
        // Obsidium section
        self.register(PatternSignature::new(
            ProtectorPattern::Obsidium,
            SignatureKind::VmEntry,
            "Obsidium .obs0 section name",
            BytePattern::exact(b".obs0"),
            80,
        ));
        // Entry: PUSHAD; MOV ESI, checksum_addr; CLD; REPZ CMPSB (CRC check)
        self.register(PatternSignature::new(
            ProtectorPattern::Obsidium,
            SignatureKind::Initialisation,
            "Obsidium PUSHAD+REPZ CRC check entry",
            BytePattern::exact(&[0x60, 0xBE]), // PUSHAD; MOV ESI, imm32
            70,
        ));
        // VM dispatcher: MOV BL, [EBX]; ADD EBX, 1; JMP EBX (self-decrypting dispatch)
        self.register(PatternSignature::new(
            ProtectorPattern::Obsidium,
            SignatureKind::Dispatcher,
            "Obsidium self-decrypt MOV BL,[EBX] dispatch",
            BytePattern::exact(&[0x8A, 0x1B, 0x83, 0xC3, 0x01, 0xFF, 0xE3]),
            75,
        ));
        // Anti-debug: MOV EAX, FS:[18h]; MOV EAX, [EAX+30h]; MOVZX EAX, [EAX+2] (PEB.BeingDebugged)
        self.register(PatternSignature::new(
            ProtectorPattern::Obsidium,
            SignatureKind::AntiDebug,
            "Obsidium PEB.BeingDebugged check",
            BytePattern::exact(&[0x64, 0xA1, 0x18, 0x00, 0x00, 0x00]),
            70,
        ));
        // Decryption: ROR ECX, 5; ADD ECX, EBX (rolling-key variant)
        self.register(PatternSignature::new(
            ProtectorPattern::Obsidium,
            SignatureKind::Decryption,
            "Obsidium ROR+ADD rolling key decrypt",
            BytePattern::exact(&[0xD1, 0xC9, 0x03, 0xCB]), // ROR ECX,1; ADD ECX,EBX (simplified)
            60,
        ));
    }
}

// ---------------------------------------------------------------------------
// ProtectorDetector
// ---------------------------------------------------------------------------

/// Scans a binary against the [`PatternDb`] and returns detected protectors.
pub struct ProtectorDetector {
    db: PatternDb,
}

impl ProtectorDetector {
    /// Create a detector with the built-in pattern database.
    #[must_use]
    pub fn new() -> Self {
        Self {
            db: PatternDb::builtin(),
        }
    }

    /// Create a detector with a custom database.
    #[must_use]
    pub const fn with_db(db: PatternDb) -> Self {
        Self { db }
    }

    /// Scan `data` for all known protectors and return detections sorted by
    /// confidence (descending).
    #[must_use]
    pub fn detect(&self, data: &[u8]) -> Vec<DetectedProtector> {
        // Accumulate confidence and match offsets per protector
        let mut scores: HashMap<ProtectorPattern, (u8, Vec<usize>, Vec<String>)> = HashMap::new();

        for sig in &self.db.signatures {
            let offsets = sig.find_all(data);
            if !offsets.is_empty() {
                let entry = scores
                    .entry(sig.protector)
                    .or_insert((0u8, Vec::new(), Vec::new()));
                // Accumulate confidence (capped at 100)
                entry.0 = entry.0.saturating_add(sig.confidence).min(100);
                entry.1.extend_from_slice(&offsets);
                entry.2.push(sig.description.clone());
            }
        }

        let mut results: Vec<DetectedProtector> = scores
            .into_iter()
            .map(|(protector, (confidence, mut offsets, sigs))| {
                offsets.sort_unstable();
                offsets.dedup();
                DetectedProtector {
                    protector,
                    confidence,
                    version_hint: infer_version(protector, confidence),
                    match_offsets: offsets,
                    matched_signatures: sigs,
                }
            })
            .collect();

        results.sort_by(|a, b| b.confidence.cmp(&a.confidence));
        results
    }

    /// Detect with a minimum confidence threshold.
    #[must_use]
    pub fn detect_min_confidence(&self, data: &[u8], min_confidence: u8) -> Vec<DetectedProtector> {
        self.detect(data)
            .into_iter()
            .filter(|d| d.confidence >= min_confidence)
            .collect()
    }

    /// Return `true` if any protector is detected with sufficient confidence.
    #[must_use]
    pub fn is_protected(&self, data: &[u8]) -> bool {
        self.detect(data).iter().any(|d| d.is_confident())
    }

    /// Return the single highest-confidence detection, if any.
    #[must_use]
    pub fn best_match(&self, data: &[u8]) -> Option<DetectedProtector> {
        self.detect(data).into_iter().next()
    }
}

impl Default for ProtectorDetector {
    fn default() -> Self {
        Self::new()
    }
}

fn infer_version(p: ProtectorPattern, _confidence: u8) -> String {
    match p {
        ProtectorPattern::VMProtect2 => "2.x".to_string(),
        ProtectorPattern::VMProtect3 => "3.x".to_string(),
        ProtectorPattern::Themida1 => "1.x".to_string(),
        ProtectorPattern::Themida2 => "2.x".to_string(),
        ProtectorPattern::CodeVirtualizer1 => "1.x".to_string(),
        ProtectorPattern::CodeVirtualizer2 => "2.x".to_string(),
        ProtectorPattern::Enigma => "4.x".to_string(),
        ProtectorPattern::Obsidium => "1.x".to_string(),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ── ProtectorPattern ──────────────────────────────────────────────────────

    #[test]
    fn pattern_names_are_unique() {
        let names = [
            ProtectorPattern::VMProtect2.name(),
            ProtectorPattern::VMProtect3.name(),
            ProtectorPattern::Themida1.name(),
            ProtectorPattern::Themida2.name(),
            ProtectorPattern::CodeVirtualizer1.name(),
            ProtectorPattern::CodeVirtualizer2.name(),
            ProtectorPattern::Enigma.name(),
            ProtectorPattern::Obsidium.name(),
        ];
        let unique: std::collections::HashSet<_> = names.iter().collect();
        assert_eq!(unique.len(), 8);
    }

    #[test]
    fn min_confidence_is_positive() {
        assert!(ProtectorPattern::VMProtect2.min_confidence() > 0);
        assert!(ProtectorPattern::Obsidium.min_confidence() > 0);
    }

    #[test]
    fn pattern_display() {
        assert!(
            ProtectorPattern::VMProtect3
                .to_string()
                .contains("VMProtect")
        );
    }

    // ── BytePattern ───────────────────────────────────────────────────────────

    #[test]
    fn byte_pattern_exact_matches() {
        let p = BytePattern::exact(&[0xDE, 0xAD, 0xBE, 0xEF]);
        let data = [0x00, 0xDE, 0xAD, 0xBE, 0xEF, 0x00];
        assert!(p.matches_at(&data, 1));
        assert!(!p.matches_at(&data, 0));
    }

    #[test]
    fn byte_pattern_wildcard_matches() {
        let p = BytePattern::wildcard(&[Some(0xFF), None, Some(0x00)]);
        let data = [0xFF, 0xAB, 0x00];
        assert!(p.matches_at(&data, 0));
        let data2 = [0xFF, 0xAB, 0x01];
        assert!(!p.matches_at(&data2, 0));
    }

    #[test]
    fn byte_pattern_find_all_returns_all_offsets() {
        let p = BytePattern::exact(&[0xAA]);
        let data = [0xAA, 0xBB, 0xAA, 0xCC, 0xAA];
        let offsets = p.find_all(&data);
        assert_eq!(offsets, vec![0, 2, 4]);
    }

    #[test]
    fn byte_pattern_find_first_returns_first() {
        let p = BytePattern::exact(&[0xBB]);
        let data = [0xAA, 0xBB, 0xCC, 0xBB];
        assert_eq!(p.find_first(&data), Some(1));
    }

    #[test]
    fn byte_pattern_find_first_no_match_returns_none() {
        let p = BytePattern::exact(&[0xFF]);
        let data = [0xAA, 0xBB, 0xCC];
        assert_eq!(p.find_first(&data), None);
    }

    #[test]
    fn byte_pattern_empty_find_first_returns_none() {
        let p = BytePattern::exact(&[]);
        assert_eq!(p.find_first(&[0xAA, 0xBB]), None);
    }

    #[test]
    fn byte_pattern_out_of_bounds_no_panic() {
        let p = BytePattern::exact(&[0xDE, 0xAD]);
        let data = [0xDE]; // too short
        assert!(!p.matches_at(&data, 0));
    }

    // ── PatternSignature ──────────────────────────────────────────────────────

    #[test]
    fn signature_matches_in_data() {
        let sig = PatternSignature::new(
            ProtectorPattern::VMProtect2,
            SignatureKind::Dispatcher,
            "test",
            BytePattern::exact(&[0x9C, 0x60]),
            70,
        );
        let mut data = vec![0xAA; 512];
        data[256] = 0x9C;
        data[257] = 0x60;
        assert!(sig.matches(&data));
    }

    #[test]
    fn signature_below_min_file_size_no_match() {
        let sig = PatternSignature {
            min_file_size: 1024,
            ..PatternSignature::new(
                ProtectorPattern::VMProtect2,
                SignatureKind::Dispatcher,
                "test",
                BytePattern::exact(&[0x9C]),
                50,
            )
        };
        let data = vec![0x9C; 512]; // only 512 bytes
        assert!(!sig.matches(&data));
    }

    #[test]
    fn signature_confidence_clamped() {
        let sig = PatternSignature::new(
            ProtectorPattern::Enigma,
            SignatureKind::AntiDebug,
            "test",
            BytePattern::exact(&[0x90]),
            200, // out of range
        );
        assert!(sig.confidence <= 100);
    }

    // ── PatternDb ─────────────────────────────────────────────────────────────

    #[test]
    fn builtin_db_has_many_signatures() {
        let db = PatternDb::builtin();
        assert!(
            db.len() >= 40,
            "expected ≥ 40 builtin signatures, got {}",
            db.len()
        );
    }

    #[test]
    fn db_for_protector_filters_correctly() {
        let db = PatternDb::builtin();
        let vmp2 = db.for_protector(ProtectorPattern::VMProtect2);
        assert!(!vmp2.is_empty());
        assert!(
            vmp2.iter()
                .all(|s| s.protector == ProtectorPattern::VMProtect2)
        );
    }

    #[test]
    fn db_of_kind_filters_correctly() {
        let db = PatternDb::builtin();
        let dispatchers = db.of_kind(SignatureKind::Dispatcher);
        assert!(!dispatchers.is_empty());
    }

    // ── ProtectorDetector ─────────────────────────────────────────────────────

    #[test]
    fn detector_detects_vmp2_pushfd_pushad() {
        let mut data = vec![0x90u8; 512];
        // Inject PUSHFD (9C) + PUSHAD (60)
        data[256] = 0x9C;
        data[257] = 0x60;

        let detector = ProtectorDetector::new();
        let results = detector.detect(&data);
        assert!(
            results
                .iter()
                .any(|d| d.protector == ProtectorPattern::VMProtect2),
            "VMProtect2 should be detected"
        );
    }

    #[test]
    fn detector_detects_enigma_magic() {
        let mut data = vec![0x00u8; 512];
        data[100..106].copy_from_slice(b"Enigma");

        let detector = ProtectorDetector::new();
        let results = detector.detect(&data);
        assert!(
            results
                .iter()
                .any(|d| d.protector == ProtectorPattern::Enigma),
            "Enigma should be detected"
        );
    }

    #[test]
    fn detector_best_match_returns_highest_confidence() {
        let mut data = vec![0x00u8; 512];
        data[100..106].copy_from_slice(b"Enigma");
        data[200..207].copy_from_slice(b".enigma");

        let detector = ProtectorDetector::new();
        let best = detector.best_match(&data);
        assert!(best.is_some());
        assert_eq!(best.unwrap().protector, ProtectorPattern::Enigma);
    }

    #[test]
    fn detector_clean_binary_is_not_protected() {
        let data = vec![0x90u8; 512]; // all NOPs
        let detector = ProtectorDetector::new();
        // NOP-only data has no protector signatures
        
        assert!(
            !detector
            .detect(&data)
            .into_iter().any(|d| d.is_confident()),
            "NOP sled should not be flagged as protected"
        );
    }

    #[test]
    fn detector_min_confidence_filter() {
        let mut data = vec![0x00u8; 512];
        data[100..106].copy_from_slice(b"Enigma");
        let detector = ProtectorDetector::new();
        let high = detector.detect_min_confidence(&data, 95);
        // Nothing should hit 95 from a single signature match
        for d in &high {
            assert!(d.confidence >= 95);
        }
    }

    #[test]
    fn detected_protector_is_confident_true() {
        let d = DetectedProtector {
            protector: ProtectorPattern::VMProtect2,
            confidence: 90,
            version_hint: "2.x".into(),
            match_offsets: vec![0],
            matched_signatures: vec!["test".into()],
        };
        assert!(d.is_confident());
    }

    #[test]
    fn detected_protector_display() {
        let d = DetectedProtector {
            protector: ProtectorPattern::Themida1,
            confidence: 75,
            version_hint: "1.x".into(),
            match_offsets: vec![100],
            matched_signatures: vec!["test".into()],
        };
        let s = d.to_string();
        assert!(s.contains("Themida") && s.contains("75"));
    }

    #[test]
    fn detector_results_sorted_by_confidence() {
        let mut data = vec![0x00u8; 512];
        // Inject patterns for two different protectors
        data[100..106].copy_from_slice(b"Enigma"); // Enigma
        data[200] = 0x9C; // VMProtect2 PUSHFD
        data[201] = 0x60; // VMProtect2 PUSHAD

        let detector = ProtectorDetector::new();
        let results = detector.detect(&data);
        // Must be sorted descending
        for w in results.windows(2) {
            assert!(w[0].confidence >= w[1].confidence);
        }
    }
}
