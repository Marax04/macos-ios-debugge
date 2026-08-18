//! `vmprotect_handler` — VMProtect 3.x handler identification and analysis.
//!
//! Covers:
//! * Protection mode identification: `VirtualProtect`, `VirtualMachine`, `Mutation`
//! * Dispatcher pattern recognition (`jmp [reg]` encrypted dispatch)
//! * VM entry/exit stub detection
//! * Register mapping recovery (x64 host → guest slot)
//! * Stack-based vs register-based VM distinction
//! * Anti-debug check removal (RDTSC, IsDebuggerPresent, NtQueryInformationProcess)


use std::collections::HashMap;

use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────────────────────
// Protection mode
// ─────────────────────────────────────────────────────────────────────────────

/// VMProtect 3.x code-protection mode applied to a given code region.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Vmp3Mode {
    /// Original code is preserved; only obfuscation and packing applied.
    VirtualProtect,
    /// Code is translated to VMProtect's proprietary bytecode VM.
    VirtualMachine,
    /// Code is mutated (multiple equivalent instruction sequences).
    Mutation,
    /// Combined: mutation _and_ VM-translation.
    MutationPlusVm,
    /// Unknown / could not be determined.
    Unknown,
}

impl std::fmt::Display for Vmp3Mode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Vmp3Mode::VirtualProtect => write!(f, "VirtualProtect"),
            Vmp3Mode::VirtualMachine => write!(f, "VirtualMachine"),
            Vmp3Mode::Mutation => write!(f, "Mutation"),
            Vmp3Mode::MutationPlusVm => write!(f, "Mutation+VM"),
            Vmp3Mode::Unknown => write!(f, "Unknown"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// VM architecture (stack vs register)
// ─────────────────────────────────────────────────────────────────────────────

/// Whether the VM uses a stack or a register-file for intermediate values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VmpVmArch {
    /// Classic VMProtect 2/3: stack-based, RSP/RBP point into the VM stack.
    StackBased,
    /// VMProtect 3 "enhanced" mode: explicit register file in a context block.
    RegisterBased,
    /// Could not determine.
    Unknown,
}

// ─────────────────────────────────────────────────────────────────────────────
// Register mapping
// ─────────────────────────────────────────────────────────────────────────────

/// Maps a VMProtect guest register slot to the x64 host register used to hold it
/// during handler execution.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VmpRegisterMapping {
    /// Guest slot index (0 = vSP, 1 = vIP, 2..N = general-purpose).
    pub guest_slot: u8,
    /// x64 register name (e.g. `"rbp"`, `"r12"`).
    pub host_reg: String,
    /// Offset within the VM context block (for register-file VMs), if known.
    pub context_offset: Option<i32>,
    /// Confidence that this mapping is correct (0.0–1.0).
    pub confidence: f32,
}

impl VmpRegisterMapping {
    /// Construct a mapping with full confidence.
    pub fn certain(guest_slot: u8, host_reg: impl Into<String>) -> Self {
        Self {
            guest_slot,
            host_reg: host_reg.into(),
            context_offset: None,
            confidence: 1.0,
        }
    }

    /// Construct a mapping with a context offset.
    pub fn with_offset(
        guest_slot: u8,
        host_reg: impl Into<String>,
        offset: i32,
        confidence: f32,
    ) -> Self {
        Self {
            guest_slot,
            host_reg: host_reg.into(),
            context_offset: Some(offset),
            confidence,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Dispatcher pattern
// ─────────────────────────────────────────────────────────────────────────────

/// Variant of the encrypted dispatch stub seen in VMProtect handlers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VmpDispatchPattern {
    /// `jmp [reg]` — indirect jump through a handler-table entry.
    IndirectJmpReg,
    /// `jmp [reg + disp32]` — indexed handler table.
    IndirectJmpRegDisp,
    /// `push reg; ret` — disguised indirect jump via stack.
    PushRet,
    /// `call reg` followed by immediate `jmp`.
    CallReg,
    /// Handler pointer is XOR-encrypted; decrypt then jump.
    XorEncrypted,
    /// Unknown dispatch variant.
    Unknown,
}

/// A single VM dispatcher stub identified in the binary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmpDispatcher {
    /// Virtual address of the dispatch instruction.
    pub address: u64,
    /// Which dispatch pattern is used.
    pub pattern: VmpDispatchPattern,
    /// XOR key used for pointer encryption (if `pattern == XorEncrypted`).
    pub xor_key: Option<u64>,
    /// Estimated handler-table base address.
    pub handler_table_base: Option<u64>,
    /// Number of handlers in the table (0 = unknown).
    pub handler_count: u16,
    /// Confidence score (0.0–1.0).
    pub confidence: f32,
}

impl VmpDispatcher {
    /// Create a new dispatcher with minimal information.
    pub fn new(address: u64, pattern: VmpDispatchPattern, confidence: f32) -> Self {
        Self {
            address,
            pattern,
            xor_key: None,
            handler_table_base: None,
            handler_count: 0,
            confidence,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// VM entry / exit stub
// ─────────────────────────────────────────────────────────────────────────────

/// Kind of VM transition stub.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VmpStubKind {
    /// Saves host registers, sets up VM context, jumps to dispatcher.
    Entry,
    /// Tears down VM context, restores host registers, returns to native code.
    Exit,
    /// Both entry and exit in a single thunk (unusual).
    EntryExit,
}

/// A VM entry or exit stub found in the binary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmpStub {
    /// Address of the stub.
    pub address: u64,
    /// Number of bytes in the stub.
    pub size_bytes: u32,
    /// Entry or exit kind.
    pub kind: VmpStubKind,
    /// Address of the corresponding dispatcher (if known).
    pub dispatcher_address: Option<u64>,
    /// Registers saved/restored by this stub.
    pub saved_registers: Vec<String>,
    /// Confidence score.
    pub confidence: f32,
}

// ─────────────────────────────────────────────────────────────────────────────
// Anti-debug check
// ─────────────────────────────────────────────────────────────────────────────

/// An anti-debug technique detected in the VMProtect-protected binary.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum VmpAntiDebugKind {
    /// `RDTSC` timing check (delta too large → debugger suspected).
    Rdtsc,
    /// `IsDebuggerPresent` Win32 API call.
    IsDebuggerPresent,
    /// `CheckRemoteDebuggerPresent` call.
    CheckRemoteDebugger,
    /// `NtQueryInformationProcess` with `ProcessDebugPort`.
    NtQueryInfoProcess,
    /// PEB.NtGlobalFlag check (offset 0x68 / 0xBC).
    PebNtGlobalFlag,
    /// Exception-based timing check (`SetUnhandledExceptionFilter` trick).
    ExceptionTiming,
    /// Heap flags in PEB (ForceFlags).
    HeapFlags,
    /// Parent process name check.
    ParentProcessCheck,
    /// Self-CRC integrity check masquerading as anti-debug.
    SelfCrc,
    /// Unknown anti-debug pattern.
    Unknown(String),
}

/// A single anti-debug check found in the binary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmpAntiDebugCheck {
    /// Address of the check.
    pub address: u64,
    /// What kind of anti-debug it is.
    pub kind: VmpAntiDebugKind,
    /// The bytes that implement the check (for NOP-patching).
    pub check_bytes: Vec<u8>,
    /// Suggested replacement bytes (typically NOPs).
    pub patch_bytes: Vec<u8>,
    /// Confidence score.
    pub confidence: f32,
}

impl VmpAntiDebugCheck {
    /// Return whether this check can be removed by simple NOP patching.
    pub fn is_noppable(&self) -> bool {
        !self.patch_bytes.is_empty()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Handler identification result
// ─────────────────────────────────────────────────────────────────────────────

/// Classification of a single VMProtect handler body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmpHandlerInfo {
    /// Virtual address of the handler.
    pub address: u64,
    /// Semantic name (e.g. `"PUSH_CONST"`, `"ADD_REG"`, `"JCC"`).
    pub semantic_name: String,
    /// Handler index in the dispatch table (0xFF = unknown).
    pub handler_index: u8,
    /// Handler body bytes.
    pub body: Vec<u8>,
    /// Register mapping relevant to this handler.
    pub register_mapping: Vec<VmpRegisterMapping>,
    /// Whether the handler operates on 32-bit or 64-bit values.
    pub operand_width: u8,
    /// Confidence that the semantic classification is correct.
    pub confidence: f32,
}

// ─────────────────────────────────────────────────────────────────────────────
// VmpAnalysisResult — top-level output
// ─────────────────────────────────────────────────────────────────────────────

/// Complete VMProtect 3.x analysis result for a single protected region.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmpAnalysisResult {
    /// Base address of the protected region.
    pub region_base: u64,
    /// Detected protection mode.
    pub mode: Vmp3Mode,
    /// VM architecture (stack vs register).
    pub vm_arch: VmpVmArch,
    /// All dispatcher stubs found.
    pub dispatchers: Vec<VmpDispatcher>,
    /// All VM entry/exit stubs found.
    pub stubs: Vec<VmpStub>,
    /// All identified handlers.
    pub handlers: Vec<VmpHandlerInfo>,
    /// Recovered register mappings (guest slot → host reg).
    pub register_map: Vec<VmpRegisterMapping>,
    /// Anti-debug checks found.
    pub anti_debug_checks: Vec<VmpAntiDebugCheck>,
    /// Overall confidence that this region is VMProtect 3.x.
    pub overall_confidence: f32,
}

impl VmpAnalysisResult {
    /// Create an empty result for the given region.
    pub fn new(region_base: u64) -> Self {
        Self {
            region_base,
            mode: Vmp3Mode::Unknown,
            vm_arch: VmpVmArch::Unknown,
            dispatchers: Vec::new(),
            stubs: Vec::new(),
            handlers: Vec::new(),
            register_map: Vec::new(),
            anti_debug_checks: Vec::new(),
            overall_confidence: 0.0,
        }
    }

    /// Number of handlers that were successfully classified.
    pub fn classified_handler_count(&self) -> usize {
        self.handlers.iter().filter(|h| h.confidence >= 0.6).count()
    }

    /// Return all anti-debug checks that can be NOP-patched.
    pub fn noppable_checks(&self) -> Vec<&VmpAntiDebugCheck> {
        self.anti_debug_checks
            .iter()
            .filter(|c| c.is_noppable())
            .collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// VmpHandlerIdentifier
// ─────────────────────────────────────────────────────────────────────────────

/// Core analyzer: identifies VMProtect 3.x handlers, stubs, dispatchers,
/// register mappings, and anti-debug checks.
pub struct VmpHandlerIdentifier {
    /// Minimum confidence threshold to accept a finding.
    pub min_confidence: f32,
    /// Whether to include low-confidence speculative findings.
    pub speculative: bool,
    /// Known VMProtect 3.x handler byte signatures (opcode → patterns).
    handler_signatures: HashMap<String, Vec<Vec<u8>>>,
    /// Known anti-debug byte patterns.
    antidebug_patterns: Vec<(VmpAntiDebugKind, Vec<u8>)>,
}

impl Default for VmpHandlerIdentifier {
    fn default() -> Self {
        Self::new()
    }
}

impl VmpHandlerIdentifier {
    /// Create with default settings and built-in signatures.
    pub fn new() -> Self {
        let mut id = Self {
            min_confidence: 0.55,
            speculative: false,
            handler_signatures: HashMap::new(),
            antidebug_patterns: Vec::new(),
        };
        id.load_builtin_handler_signatures();
        id.load_antidebug_patterns();
        id
    }

    /// Set confidence threshold.
    pub fn with_min_confidence(mut self, t: f32) -> Self {
        self.min_confidence = t;
        self
    }

    /// Enable speculative (low-confidence) findings.
    pub fn with_speculative(mut self, s: bool) -> Self {
        self.speculative = s;
        self
    }

    // ── Load built-in handler signatures ─────────────────────────────────────

    fn load_builtin_handler_signatures(&mut self) {
        // VMProtect 3 x64 — PUSH_CONST handler prologue
        // mov rax, imm64; push rax; sub rbp, 8; mov [rbp], rax
        self.handler_signatures.insert(
            "PUSH_CONST".into(),
            vec![
                vec![0x48, 0xB8],            // mov rax, imm64 prefix
                vec![0x48, 0xC7, 0xC0],      // mov rax, imm32 (sign-extended)
            ],
        );

        // ADD_REG: pop rax; pop rbx; add rax, rbx; push rax
        self.handler_signatures.insert(
            "ADD_REG".into(),
            vec![
                vec![0x58, 0x5B, 0x48, 0x01, 0xD8, 0x50],
                vec![0x58, 0x5A, 0x48, 0x01, 0xD0, 0x50],
            ],
        );

        // SUB_REG: pop rax; pop rbx; sub rax, rbx; push rax
        self.handler_signatures.insert(
            "SUB_REG".into(),
            vec![
                vec![0x58, 0x5B, 0x48, 0x29, 0xD8, 0x50],
            ],
        );

        // XOR_REG
        self.handler_signatures.insert(
            "XOR_REG".into(),
            vec![
                vec![0x58, 0x5B, 0x48, 0x31, 0xD8, 0x50],
            ],
        );

        // AND_REG
        self.handler_signatures.insert(
            "AND_REG".into(),
            vec![
                vec![0x58, 0x5B, 0x48, 0x21, 0xD8, 0x50],
            ],
        );

        // NOT_REG
        self.handler_signatures.insert(
            "NOT_REG".into(),
            vec![
                vec![0x58, 0x48, 0xF7, 0xD0, 0x50],
            ],
        );

        // NEG_REG
        self.handler_signatures.insert(
            "NEG_REG".into(),
            vec![
                vec![0x58, 0x48, 0xF7, 0xD8, 0x50],
            ],
        );

        // SHL_REG: pop rcx; pop rax; shl rax, cl; push rax
        self.handler_signatures.insert(
            "SHL_REG".into(),
            vec![
                vec![0x59, 0x58, 0x48, 0xD3, 0xE0, 0x50],
            ],
        );

        // SHR_REG
        self.handler_signatures.insert(
            "SHR_REG".into(),
            vec![
                vec![0x59, 0x58, 0x48, 0xD3, 0xE8, 0x50],
            ],
        );

        // JMP (unconditional dispatch)
        self.handler_signatures.insert(
            "JMP".into(),
            vec![
                vec![0x58, 0xFF, 0xE0],       // pop rax; jmp rax
                vec![0xFF, 0x25],              // jmp [rip+disp32]
            ],
        );

        // JCC (conditional)
        self.handler_signatures.insert(
            "JCC".into(),
            vec![
                vec![0x58, 0x85, 0xC0],       // pop rax; test eax, eax
                vec![0x58, 0x48, 0x85, 0xC0], // pop rax; test rax, rax
            ],
        );

        // LOAD (memory fetch into stack)
        self.handler_signatures.insert(
            "LOAD".into(),
            vec![
                vec![0x58, 0x48, 0x8B, 0x00, 0x50], // pop rax; mov rax,[rax]; push rax
                vec![0x5F, 0x48, 0x8B, 0x07, 0x57], // pop rdi; mov rax,[rdi]; push rdi (32-bit variant)
            ],
        );

        // STORE
        self.handler_signatures.insert(
            "STORE".into(),
            vec![
                vec![0x58, 0x5B, 0x48, 0x89, 0x18], // pop rax; pop rbx; mov [rax], rbx
            ],
        );

        // CALL
        self.handler_signatures.insert(
            "CALL".into(),
            vec![
                vec![0x58, 0xFF, 0xD0],       // pop rax; call rax
            ],
        );

        // RET
        self.handler_signatures.insert(
            "RET".into(),
            vec![
                vec![0xC3],
                vec![0xC2],
            ],
        );
    }

    // ── Load anti-debug patterns ──────────────────────────────────────────────

    fn load_antidebug_patterns(&mut self) {
        // RDTSC timing: 0F 31 (rdtsc)
        self.antidebug_patterns
            .push((VmpAntiDebugKind::Rdtsc, vec![0x0F, 0x31]));

        // IsDebuggerPresent: FF 15 xx xx xx xx (call [IsDebuggerPresent IAT entry])
        // We store just the call-through-import prefix; actual match uses the import table
        self.antidebug_patterns
            .push((VmpAntiDebugKind::IsDebuggerPresent, vec![0x64, 0x48, 0x8B, 0x04, 0x25])); // TEB access

        // PEB.NtGlobalFlag (x64): mov rax, [gs:0x60]; movzx eax, byte ptr [rax+0xBC]
        self.antidebug_patterns.push((
            VmpAntiDebugKind::PebNtGlobalFlag,
            vec![0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00],
        ));

        // HeapFlags: mov eax, [rax+0x14] (ForceFlags at +0x14 in heap header)
        self.antidebug_patterns.push((
            VmpAntiDebugKind::HeapFlags,
            vec![0x8B, 0x40, 0x14],
        ));

        // CheckRemoteDebuggerPresent: NtQueryInformationProcess prologue
        // mov eax, 16 (NtQueryInformationProcess syscall nr — varies by OS)
        self.antidebug_patterns.push((
            VmpAntiDebugKind::NtQueryInfoProcess,
            vec![0xB8, 0x19, 0x00, 0x00, 0x00, 0x0F, 0x05], // syscall path
        ));
    }

    // ── Protection-mode detection ─────────────────────────────────────────────

    /// Detect the VMProtect mode applied to `bytes` (a code region).
    /// Returns [`Vmp3Mode`] and a confidence score.
    pub fn detect_mode(&self, bytes: &[u8]) -> (Vmp3Mode, f32) {
        if bytes.len() < 16 {
            return (Vmp3Mode::Unknown, 0.0);
        }

        let mut vm_score: f32 = 0.0;
        let mut mutation_score: f32 = 0.0;
        let mut protect_score: f32 = 0.0;

        // Heuristic 1: presence of encrypted jmp [reg] dispatch → VM mode
        let encrypted_dispatch_score = self.score_encrypted_dispatch(bytes);
        vm_score += encrypted_dispatch_score * 0.45;

        // Heuristic 2: high instruction entropy → mutation or VM packing
        let entropy = byte_entropy(bytes);
        if entropy > 7.2 {
            vm_score += 0.15;
            mutation_score += 0.10;
        } else if entropy > 6.5 {
            mutation_score += 0.20;
            protect_score += 0.10;
        }

        // Heuristic 3: unusual register usage patterns → mutation
        let unusual_regs = count_unusual_register_sequences(bytes);
        if unusual_regs > 5 {
            mutation_score += 0.25;
        } else if unusual_regs > 2 {
            mutation_score += 0.10;
        }

        // Heuristic 4: PUSHAD/POPAD or full context save → VirtualProtect packer entry
        if contains_subslice(bytes, &[0x60]) || contains_subslice(bytes, &[0x61]) {
            protect_score += 0.20;
        }

        // Heuristic 5: stack-frame setup without standard prologue → VM
        let missing_prologue = !contains_subslice(bytes, &[0x55, 0x48, 0x89, 0xE5])
            && !contains_subslice(bytes, &[0x55, 0x8B, 0xEC]);
        if missing_prologue && bytes.len() > 64 {
            vm_score += 0.15;
        }

        // Resolve winner
        let max_score = vm_score.max(mutation_score).max(protect_score);
        if max_score < 0.25 {
            return (Vmp3Mode::Unknown, max_score);
        }

        if vm_score >= mutation_score && vm_score >= protect_score {
            if mutation_score > 0.3 {
                (Vmp3Mode::MutationPlusVm, (vm_score + mutation_score) / 2.0)
            } else {
                (Vmp3Mode::VirtualMachine, vm_score.min(1.0))
            }
        } else if mutation_score >= protect_score {
            (Vmp3Mode::Mutation, mutation_score.min(1.0))
        } else {
            (Vmp3Mode::VirtualProtect, protect_score.min(1.0))
        }
    }

    /// Score how likely `bytes` contains an encrypted `jmp [reg]` dispatch loop.
    fn score_encrypted_dispatch(&self, bytes: &[u8]) -> f32 {
        let mut score: f32 = 0.0;

        for window in bytes.windows(3) {
            match window {
                // FF E0 → jmp rax
                [0xFF, 0xE0, _] => score += 0.15,
                // FF E1 → jmp rcx
                [0xFF, 0xE1, _] => score += 0.15,
                // FF 25 → jmp [rip+disp32]
                [0xFF, 0x25, _] => score += 0.10,
                _ => {}
            }
        }

        // push X; ret pattern
        for i in 0..bytes.len().saturating_sub(1) {
            if bytes[i] == 0x50 && bytes[i + 1] == 0xC3 {
                score += 0.10; // push rax; ret
            }
            if bytes[i] == 0x57 && bytes[i + 1] == 0xC3 {
                score += 0.10; // push rdi; ret
            }
        }

        score.min(1.0)
    }

    // ── Dispatcher identification ─────────────────────────────────────────────

    /// Find all VM dispatchers in `bytes` (starting at `base_address`).
    pub fn find_dispatchers(&self, bytes: &[u8], base_address: u64) -> Vec<VmpDispatcher> {
        let mut result = Vec::new();

        for i in 0..bytes.len() {
            let window = &bytes[i..];
            let addr = base_address + i as u64;

            // Pattern: jmp [rax] / jmp [rcx] / jmp [rdx]
            if window.len() >= 2 && window[0] == 0xFF {
                let pattern = match window[1] {
                    0xE0 => Some((VmpDispatchPattern::IndirectJmpReg, 0.75)),
                    0xE1 => Some((VmpDispatchPattern::IndirectJmpReg, 0.75)),
                    0xE2 => Some((VmpDispatchPattern::IndirectJmpReg, 0.70)),
                    0xE3 => Some((VmpDispatchPattern::IndirectJmpReg, 0.65)),
                    0x25 => Some((VmpDispatchPattern::IndirectJmpReg, 0.60)),
                    _ => None,
                };
                if let Some((pat, conf)) = pattern {
                    if conf >= self.min_confidence || self.speculative {
                        result.push(VmpDispatcher::new(addr, pat, conf));
                    }
                }
            }

            // Pattern: push rax; ret (PushRet disguised jmp)
            if window.len() >= 2 && matches!(window[0], 0x50..=0x57) && window[1] == 0xC3 {
                let conf = 0.60;
                if conf >= self.min_confidence || self.speculative {
                    result.push(VmpDispatcher::new(addr, VmpDispatchPattern::PushRet, conf));
                }
            }

            // Pattern: XOR key decryption before jmp [reg]
            // xor rax, imm32 followed by jmp [rax]
            if window.len() >= 10
                && window[0] == 0x48
                && window[1] == 0x35  // xor rax, imm32 (REX.W prefix)
            {
                let key_bytes = &window[2..6];
                let xor_key = u32::from_le_bytes(key_bytes.try_into().unwrap_or_default()) as u64;
                if window[6] == 0xFF && window[7] == 0xE0 {
                    let conf = 0.85;
                    let mut d = VmpDispatcher::new(addr, VmpDispatchPattern::XorEncrypted, conf);
                    d.xor_key = Some(xor_key);
                    result.push(d);
                }
            }
        }

        result
    }

    // ── Entry/exit stub detection ─────────────────────────────────────────────

    /// Detect VM entry and exit stubs in `bytes`.
    pub fn find_stubs(&self, bytes: &[u8], base_address: u64) -> Vec<VmpStub> {
        let mut result = Vec::new();

        // Entry stub: push many registers (PUSHAQ-style), then set up VM context pointer
        // Typical VMP3 x64 entry: push rbp/rax/rbx/rcx/rdx/rsi/rdi/r8..r15, then
        //   mov rbp, rsp  (or similar context base setup)
        let entry_pattern = detect_pushaq_sequence(bytes);
        for (offset, saved_regs, size) in entry_pattern {
            let addr = base_address + offset as u64;
            result.push(VmpStub {
                address: addr,
                size_bytes: size,
                kind: VmpStubKind::Entry,
                dispatcher_address: None,
                saved_registers: saved_regs,
                confidence: 0.70,
            });
        }

        // Exit stub: POPAQ sequence restoring all registers, then ret
        let exit_pattern = detect_popaq_sequence(bytes);
        for (offset, restored_regs, size) in exit_pattern {
            let addr = base_address + offset as u64;
            result.push(VmpStub {
                address: addr,
                size_bytes: size,
                kind: VmpStubKind::Exit,
                dispatcher_address: None,
                saved_registers: restored_regs,
                confidence: 0.68,
            });
        }

        result
    }

    // ── Register mapping recovery ─────────────────────────────────────────────

    /// Recover register mappings from handler bodies.
    ///
    /// VMProtect 3 x64 (stack-based) conventionally uses:
    /// * `rbp` — virtual stack pointer (vSP)
    /// * `rsi` — virtual instruction pointer (vIP)
    /// * `rdi` — handler table pointer
    /// Other registers rotate through guest operand slots.
    pub fn recover_register_mappings(&self, stubs: &[VmpStub]) -> Vec<VmpRegisterMapping> {
        let mut mappings = Vec::new();

        // Default VMProtect 3 x64 stack-based layout (well-known, high confidence)
        mappings.push(VmpRegisterMapping::certain(0, "rbp"));  // vSP
        mappings.push(VmpRegisterMapping::certain(1, "rsi"));  // vIP
        mappings.push(VmpRegisterMapping::certain(2, "rdi"));  // handler table

        // Scan stubs for deviations from the default layout
        let has_rbp_as_sp = stubs.iter().any(|s| s.saved_registers.contains(&"rbp".to_string()));
        if !has_rbp_as_sp {
            // Non-standard layout: vSP may be in r12 or r13
            mappings.push(VmpRegisterMapping::with_offset(0, "r12", 0, 0.55));
        }

        // Guest general-purpose regs (slots 3..10) → not pinned to specific host regs;
        // mark as unknown
        for slot in 3..=10u8 {
            mappings.push(VmpRegisterMapping {
                guest_slot: slot,
                host_reg: format!("<unknown-gp{}>", slot),
                context_offset: Some((slot as i32 - 3) * 8),
                confidence: 0.35,
            });
        }

        mappings
    }

    // ── VM architecture classification ────────────────────────────────────────

    /// Classify whether the VM is stack-based or register-based.
    pub fn classify_vm_arch(&self, bytes: &[u8]) -> VmpVmArch {
        // Stack-based VMs heavily use RSP/RBP relative addressing
        let rsp_refs = count_rsp_relative(bytes);
        let rbp_refs = count_rbp_relative(bytes);

        // Register-based VMs use explicit context-block addressing with large offsets
        let ctx_refs = count_context_block_refs(bytes);

        if ctx_refs > 8 && ctx_refs > rsp_refs + rbp_refs {
            VmpVmArch::RegisterBased
        } else if rsp_refs + rbp_refs > 4 {
            VmpVmArch::StackBased
        } else {
            VmpVmArch::Unknown
        }
    }

    // ── Handler identification ────────────────────────────────────────────────

    /// Match known VMProtect 3 handler byte sequences in `body`.
    pub fn identify_handler(&self, address: u64, body: &[u8]) -> Option<VmpHandlerInfo> {
        if body.len() < 3 {
            return None;
        }

        for (semantic_name, patterns) in &self.handler_signatures {
            for pattern in patterns {
                if body_starts_with(body, pattern) {
                    let confidence = if pattern.len() >= 5 { 0.80 } else { 0.58 };
                    if confidence >= self.min_confidence || self.speculative {
                        return Some(VmpHandlerInfo {
                            address,
                            semantic_name: semantic_name.clone(),
                            handler_index: 0xFF,
                            body: body.to_vec(),
                            register_mapping: Vec::new(),
                            operand_width: infer_operand_width(body),
                            confidence,
                        });
                    }
                }
            }
        }

        // Fallback: classify by opcode density
        classify_handler_by_opcodes(address, body, self.min_confidence)
    }

    // ── Anti-debug removal ────────────────────────────────────────────────────

    /// Find all anti-debug checks in `bytes`.
    pub fn find_anti_debug_checks(&self, bytes: &[u8], base_address: u64) -> Vec<VmpAntiDebugCheck> {
        let mut result = Vec::new();

        for (kind, pattern) in &self.antidebug_patterns {
            let mut offset = 0;
            while let Some(pos) = find_subslice(&bytes[offset..], pattern) {
                let abs_pos = offset + pos;
                let addr = base_address + abs_pos as u64;
                let end = (abs_pos + pattern.len() + 8).min(bytes.len());
                let check_bytes = bytes[abs_pos..end].to_vec();
                let patch_bytes = vec![0x90u8; check_bytes.len()]; // NOP sled

                let confidence = match kind {
                    VmpAntiDebugKind::Rdtsc => 0.85,
                    VmpAntiDebugKind::PebNtGlobalFlag => 0.80,
                    VmpAntiDebugKind::NtQueryInfoProcess => 0.75,
                    _ => 0.65,
                };

                result.push(VmpAntiDebugCheck {
                    address: addr,
                    kind: kind.clone(),
                    check_bytes,
                    patch_bytes,
                    confidence,
                });

                offset = abs_pos + 1;
            }
        }

        result
    }

    // ── Full analysis ─────────────────────────────────────────────────────────

    /// Run the full VMProtect 3 analysis pipeline on a code region.
    pub fn analyze(&self, bytes: &[u8], base_address: u64) -> VmpAnalysisResult {
        let mut result = VmpAnalysisResult::new(base_address);

        let (mode, mode_conf) = self.detect_mode(bytes);
        result.mode = mode;

        result.dispatchers = self.find_dispatchers(bytes, base_address);
        result.stubs = self.find_stubs(bytes, base_address);
        result.vm_arch = self.classify_vm_arch(bytes);
        result.register_map = self.recover_register_mappings(&result.stubs);
        result.anti_debug_checks = self.find_anti_debug_checks(bytes, base_address);

        // Identify handlers in 64-byte windows centered on dispatcher addresses
        for disp in &result.dispatchers {
            let start = disp.address.saturating_sub(base_address) as usize;
            let end = (start + 128).min(bytes.len());
            if start < end {
                if let Some(info) = self.identify_handler(disp.address, &bytes[start..end]) {
                    result.handlers.push(info);
                }
            }
        }

        // Overall confidence
        let handler_conf = if result.handlers.is_empty() {
            0.0
        } else {
            result.handlers.iter().map(|h| h.confidence).sum::<f32>()
                / result.handlers.len() as f32
        };
        result.overall_confidence = (mode_conf * 0.5
            + handler_conf * 0.3
            + if result.dispatchers.is_empty() { 0.0 } else { 0.2 })
        .min(1.0);

        result
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Private helpers
// ─────────────────────────────────────────────────────────────────────────────

fn byte_entropy(bytes: &[u8]) -> f32 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut freq = [0u32; 256];
    for &b in bytes {
        freq[b as usize] += 1;
    }
    let len = bytes.len() as f32;
    freq.iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f32 / len;
            -p * p.log2()
        })
        .sum()
}

fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn body_starts_with(body: &[u8], pattern: &[u8]) -> bool {
    body.len() >= pattern.len() && &body[..pattern.len()] == pattern
}

fn count_unusual_register_sequences(bytes: &[u8]) -> usize {
    // Count REX.W prefixed instructions with r8..r15
    bytes
        .windows(2)
        .filter(|w| matches!(w[0], 0x44 | 0x45 | 0x4C | 0x4D) && w[1] != 0x00)
        .count()
}

fn count_rsp_relative(bytes: &[u8]) -> usize {
    // RSP-relative MOVs: 48 8B xx 24 (mod=01 or mod=10, r/m=RSP)
    bytes
        .windows(3)
        .filter(|w| w[0] == 0x48 && w[1] == 0x8B && (w[2] & 0x07) == 0x04)
        .count()
}

fn count_rbp_relative(bytes: &[u8]) -> usize {
    bytes
        .windows(2)
        .filter(|w| w[0] == 0x48 && (w[1] == 0x89 || w[1] == 0x8B))
        .count()
        / 3 // rough heuristic: only ~1/3 use RBP
}

fn count_context_block_refs(bytes: &[u8]) -> usize {
    // Large positive offsets from R12..R15 suggest a context block
    bytes
        .windows(4)
        .filter(|w| {
            matches!(w[0], 0x4D | 0x4C)
                && matches!(w[1], 0x8B | 0x89)
                && w[3] >= 0x10
        })
        .count()
}

fn infer_operand_width(body: &[u8]) -> u8 {
    // REX.W prefix (0x48) → 64-bit; no REX.W → 32-bit
    if body.iter().any(|&b| b == 0x48) {
        64
    } else {
        32
    }
}

/// Detect sequences of PUSH reg (50..57 or 41 50..57) for entry stub.
/// Returns `(offset, saved_reg_names, size_bytes)`.
fn detect_pushaq_sequence(bytes: &[u8]) -> Vec<(usize, Vec<String>, u32)> {
    let mut results = Vec::new();
    let reg_names_lo = ["rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi"];

    let mut i = 0;
    while i < bytes.len().saturating_sub(8) {
        if matches!(bytes[i], 0x50..=0x57) {
            let start = i;
            let mut saved = Vec::new();
            let mut j = i;
            while j < bytes.len() && matches!(bytes[j], 0x50..=0x57) {
                let idx = (bytes[j] - 0x50) as usize;
                saved.push(reg_names_lo[idx].to_string());
                j += 1;
            }
            // REX.B extensions (41 50..57)
            while j + 1 < bytes.len() && bytes[j] == 0x41 && matches!(bytes[j+1], 0x50..=0x57) {
                let idx = (bytes[j+1] - 0x50) as usize;
                saved.push(format!("r{}", 8 + idx));
                j += 2;
            }
            if saved.len() >= 8 {
                results.push((start, saved, (j - start) as u32));
            }
            i = j;
        } else {
            i += 1;
        }
    }

    results
}

/// Detect POPAQ (POP reg sequences) for exit stubs.
fn detect_popaq_sequence(bytes: &[u8]) -> Vec<(usize, Vec<String>, u32)> {
    let mut results = Vec::new();
    let reg_names = ["rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi"];

    let mut i = 0;
    while i < bytes.len().saturating_sub(8) {
        if matches!(bytes[i], 0x58..=0x5F) {
            let start = i;
            let mut restored = Vec::new();
            let mut j = i;
            while j < bytes.len() && matches!(bytes[j], 0x58..=0x5F) {
                let idx = (bytes[j] - 0x58) as usize;
                restored.push(reg_names[idx].to_string());
                j += 1;
            }
            while j + 1 < bytes.len() && bytes[j] == 0x41 && matches!(bytes[j+1], 0x58..=0x5F) {
                let idx = (bytes[j+1] - 0x58) as usize;
                restored.push(format!("r{}", 8 + idx));
                j += 2;
            }
            if restored.len() >= 8 {
                results.push((start, restored, (j - start) as u32));
            }
            i = j;
        } else {
            i += 1;
        }
    }

    results
}

fn classify_handler_by_opcodes(
    address: u64,
    body: &[u8],
    min_confidence: f32,
) -> Option<VmpHandlerInfo> {
    // Count arithmetic opcodes to guess semantic
    let add_count = body.windows(2).filter(|w| w[0] == 0x48 && w[1] == 0x01).count();
    let sub_count = body.windows(2).filter(|w| w[0] == 0x48 && w[1] == 0x29).count();
    let xor_count = body.windows(2).filter(|w| w[0] == 0x48 && w[1] == 0x31).count();
    let and_count = body.windows(2).filter(|w| w[0] == 0x48 && w[1] == 0x21).count();

    let max_count = add_count.max(sub_count).max(xor_count).max(and_count);
    if max_count == 0 {
        return None;
    }

    let (name, conf) = if add_count == max_count {
        ("ADD_REG", 0.45f32)
    } else if sub_count == max_count {
        ("SUB_REG", 0.45)
    } else if xor_count == max_count {
        ("XOR_REG", 0.45)
    } else {
        ("AND_REG", 0.45)
    };

    if conf >= min_confidence {
        Some(VmpHandlerInfo {
            address,
            semantic_name: name.to_string(),
            handler_index: 0xFF,
            body: body.to_vec(),
            register_mapping: Vec::new(),
            operand_width: infer_operand_width(body),
            confidence: conf,
        })
    } else {
        None
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_mode_empty() {
        let id = VmpHandlerIdentifier::new();
        let (mode, conf) = id.detect_mode(&[]);
        assert_eq!(mode, Vmp3Mode::Unknown);
        assert_eq!(conf, 0.0);
    }

    #[test]
    fn test_find_dispatchers_jmp_rax() {
        let id = VmpHandlerIdentifier::new();
        // FF E0 = jmp rax
        let code = vec![0x90u8, 0xFF, 0xE0, 0x90];
        let disps = id.find_dispatchers(&code, 0x1000);
        assert!(!disps.is_empty());
        assert_eq!(disps[0].address, 0x1001);
        assert_eq!(disps[0].pattern, VmpDispatchPattern::IndirectJmpReg);
    }

    #[test]
    fn test_identify_handler_add() {
        let id = VmpHandlerIdentifier::new();
        // pop rax; pop rbx; add rax, rbx; push rax
        let body = vec![0x58, 0x5B, 0x48, 0x01, 0xD8, 0x50];
        let info = id.identify_handler(0x2000, &body).unwrap();
        assert_eq!(info.semantic_name, "ADD_REG");
    }

    #[test]
    fn test_find_anti_debug_rdtsc() {
        let id = VmpHandlerIdentifier::new();
        let code = vec![0x90u8, 0x0F, 0x31, 0x90, 0x90];
        let checks = id.find_anti_debug_checks(&code, 0x5000);
        assert!(checks.iter().any(|c| c.kind == VmpAntiDebugKind::Rdtsc));
    }

    #[test]
    fn test_register_mapping_defaults() {
        let id = VmpHandlerIdentifier::new();
        let mappings = id.recover_register_mappings(&[]);
        // vSP = rbp, vIP = rsi, handler table = rdi by default
        assert!(mappings.iter().any(|m| m.guest_slot == 0 && m.host_reg == "rbp"));
        assert!(mappings.iter().any(|m| m.guest_slot == 1 && m.host_reg == "rsi"));
    }

    #[test]
    fn test_classify_vm_arch_stack() {
        let id = VmpHandlerIdentifier::new();
        // RSP-relative: 48 8B 04 24 (mov rax, [rsp]) × 5
        let bytes: Vec<u8> = (0..5)
            .flat_map(|_| vec![0x48u8, 0x8B, 0x04, 0x24])
            .collect();
        let arch = id.classify_vm_arch(&bytes);
        assert_eq!(arch, VmpVmArch::StackBased);
    }
}
