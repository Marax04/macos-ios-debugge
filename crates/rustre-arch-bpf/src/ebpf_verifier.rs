//! eBPF program verifier: register tracking, pointer safety checking.
//!
//! Implements a simplified but real abstract-interpretation–based verifier
//! that tracks register types and detects common safety violations before
//! a program is admitted for execution.

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

// ─── Register constants ───────────────────────────────────────────────────────

/// Number of eBPF registers (R0–R10).
pub const BPF_REG_COUNT: usize = 11;

/// Register index for the frame pointer (R10).
pub const BPF_REG_FP: usize = 10;

/// Register index for the return value / first argument (R0).
pub const BPF_REG_RET: usize = 0;

// ─── RegisterType ─────────────────────────────────────────────────────────────

/// Abstract type of a value held in an eBPF register.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RegisterType {
    /// Register value is not yet defined (initial state).
    Uninitialised,
    /// A numeric scalar value (may be any integer).
    Scalar,
    /// A known constant (value embedded).
    Constant(i64),
    /// A pointer to the eBPF stack frame, with offset from FP.
    FramePointer { offset: i32 },
    /// A pointer to a map value returned by a helper call.
    MapValue { map_id: u32, nullable: bool },
    /// A pointer to the packet data start (`PTR_TO_PACKET`).
    PacketData,
    /// A pointer just past the end of the packet (`PTR_TO_PACKET_END`).
    PacketEnd,
    /// A pointer to program context (`PTR_TO_CTX`).
    Context,
    /// NULL / zero pointer.
    Null,
    /// Pointer to a per-cpu array.
    PerCpuArray,
    /// Return value from an unknown helper.
    Unknown,
}

impl fmt::Display for RegisterType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Uninitialised => write!(f, "uninit"),
            Self::Scalar => write!(f, "scalar"),
            Self::Constant(v) => write!(f, "const({v})"),
            Self::FramePointer { offset } => write!(f, "fp+{offset}"),
            Self::MapValue { map_id, nullable } => {
                write!(f, "map_val(id={map_id},null={nullable})")
            }
            Self::PacketData => write!(f, "pkt_data"),
            Self::PacketEnd => write!(f, "pkt_end"),
            Self::Context => write!(f, "ctx"),
            Self::Null => write!(f, "null"),
            Self::PerCpuArray => write!(f, "percpu_array"),
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

impl RegisterType {
    /// Returns `true` if this type is a pointer (dereferenceable).
    #[must_use]
    pub const fn is_pointer(&self) -> bool {
        matches!(
            self,
            Self::FramePointer { .. }
                | Self::MapValue { .. }
                | Self::PacketData
                | Self::PacketEnd
                | Self::Context
                | Self::PerCpuArray
        )
    }

    /// Returns `true` if this type is a safe-to-dereference pointer.
    #[must_use]
    pub const fn is_safe_pointer(&self) -> bool {
        matches!(
            self,
            Self::FramePointer { .. } | Self::MapValue { nullable: false, .. } | Self::Context
        )
    }

    /// Returns `true` if this register holds a known integer.
    #[must_use]
    pub const fn is_numeric(&self) -> bool {
        matches!(self, Self::Scalar | Self::Constant(_))
    }
}

// ─── SafetyViolation ─────────────────────────────────────────────────────────

/// A safety violation detected by the verifier.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SafetyViolation {
    /// Instruction index where the violation was detected.
    pub insn_idx: usize,
    /// Human-readable description of the violation.
    pub message: String,
    /// Severity (informational, warning, error).
    pub severity: ViolationSeverity,
}

impl SafetyViolation {
    fn error(insn_idx: usize, msg: impl Into<String>) -> Self {
        Self {
            insn_idx,
            message: msg.into(),
            severity: ViolationSeverity::Error,
        }
    }

    fn warning(insn_idx: usize, msg: impl Into<String>) -> Self {
        Self {
            insn_idx,
            message: msg.into(),
            severity: ViolationSeverity::Warning,
        }
    }
}

impl fmt::Display for SafetyViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}] insn#{}: {}",
            self.severity, self.insn_idx, self.message
        )
    }
}

/// Severity levels for verifier violations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ViolationSeverity {
    Info,
    Warning,
    Error,
}

impl fmt::Display for ViolationSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Info => write!(f, "INFO"),
            Self::Warning => write!(f, "WARN"),
            Self::Error => write!(f, "ERROR"),
        }
    }
}

// ─── VerificationState ───────────────────────────────────────────────────────

/// The abstract state of all registers at a particular program point.
#[derive(Debug, Clone)]
pub struct VerificationState {
    /// Abstract type of each register R0–R10.
    pub regs: [RegisterType; BPF_REG_COUNT],
    /// Whether this state has been visited (for loop detection).
    pub visited: bool,
    /// Stack slot types: map from offset-from-FP (negative) → type.
    pub stack: HashMap<i32, RegisterType>,
}

impl VerificationState {
    /// Create the initial verification state (R1 = ctx, all others uninit,
    /// R10 = frame pointer at offset 0).
    #[must_use]
    pub fn entry() -> Self {
        let mut regs: [RegisterType; BPF_REG_COUNT] = std::array::from_fn(|_| RegisterType::Uninitialised);
        regs[1] = RegisterType::Context;
        regs[BPF_REG_FP] = RegisterType::FramePointer { offset: 0 };
        Self {
            regs,
            visited: false,
            stack: HashMap::new(),
        }
    }

    /// Create a state with all registers set to `Scalar`.
    #[must_use]
    pub fn all_scalar() -> Self {
        Self {
            regs: std::array::from_fn(|_| RegisterType::Scalar),
            visited: false,
            stack: HashMap::new(),
        }
    }

    /// Get the type of register `r`.
    #[must_use]
    pub const fn reg(&self, r: usize) -> &RegisterType {
        &self.regs[r]
    }

    /// Set the type of register `r`.
    pub const fn set_reg(&mut self, r: usize, t: RegisterType) {
        if r < BPF_REG_COUNT {
            self.regs[r] = t;
        }
    }

    /// Spill a register value to a stack slot.
    pub fn spill(&mut self, fp_offset: i32, t: RegisterType) {
        self.stack.insert(fp_offset, t);
    }

    /// Fill a register from a stack slot. Returns `Uninitialised` if the slot
    /// was never written.
    #[must_use]
    pub fn fill(&self, fp_offset: i32) -> RegisterType {
        self.stack.get(&fp_offset).cloned().unwrap_or(RegisterType::Uninitialised)
    }

    /// Join two states (least upper bound) for merging at branch targets.
    #[must_use]
    pub fn join(&self, other: &Self) -> Self {
        let regs = std::array::from_fn(|i| join_types(&self.regs[i], &other.regs[i]));
        let mut stack = self.stack.clone();
        for (k, v) in &other.stack {
            let joined = stack
                .get(k)
                .map_or_else(|| v.clone(), |existing| join_types(existing, v));
            stack.insert(*k, joined);
        }
        Self {
            regs,
            visited: false,
            stack,
        }
    }
}

fn join_types(a: &RegisterType, b: &RegisterType) -> RegisterType {
    if a == b {
        return a.clone();
    }
    match (a, b) {
        (RegisterType::Constant(x), RegisterType::Constant(y)) if x == y => {
            RegisterType::Constant(*x)
        }
        // Two differing constants, a constant meeting a scalar, and anything
        // meeting Null all widen to an unconstrained scalar.
        (RegisterType::Constant(_) | RegisterType::Scalar, RegisterType::Constant(_))
| (RegisterType::Constant(_), RegisterType::Scalar) | (RegisterType::Null, _)
| (_, RegisterType::Null) => RegisterType::Scalar,
        (RegisterType::MapValue { map_id: a_id, .. }, RegisterType::MapValue { map_id: b_id, .. }) if a_id == b_id => {
            RegisterType::MapValue { map_id: *a_id, nullable: true }
        }
        _ => RegisterType::Unknown,
    }
}

// ─── eBPF instruction encoding ───────────────────────────────────────────────

/// Raw eBPF instruction (8 bytes, little-endian).
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct EbpfInsn {
    pub code: u8,
    pub dst: u8,    // destination register (low 4 bits)
    pub src: u8,    // source register (high 4 bits)
    pub off: i16,
    pub imm: i32,
}

impl EbpfInsn {
    /// Decode from 8 raw bytes (eBPF wire format, little-endian).
    #[must_use]
    pub const fn from_bytes(b: &[u8; 8]) -> Self {
        Self {
            code: b[0],
            dst: b[1] & 0x0F,
            src: (b[1] >> 4) & 0x0F,
            off: i16::from_le_bytes([b[2], b[3]]),
            imm: i32::from_le_bytes([b[4], b[5], b[6], b[7]]),
        }
    }

    /// Encode to 8 bytes.
    #[must_use]
    pub const fn to_bytes(self) -> [u8; 8] {
        let mut out = [0u8; 8];
        out[0] = self.code;
        out[1] = (self.dst & 0x0F) | ((self.src & 0x0F) << 4);
        let off = self.off.to_le_bytes();
        out[2] = off[0];
        out[3] = off[1];
        let imm = self.imm.to_le_bytes();
        out[4] = imm[0];
        out[5] = imm[1];
        out[6] = imm[2];
        out[7] = imm[3];
        out
    }

    /// Returns the BPF instruction class (lower 3 bits of code).
    #[must_use]
    pub const fn class(self) -> u8 {
        self.code & 0x07
    }

    /// Returns `true` if this is a 64-bit arithmetic instruction.
    #[must_use]
    pub const fn is_alu64(self) -> bool {
        self.class() == 0x07
    }

    /// Returns `true` if this is a load instruction (`BPF_LD`=0x00 or `BPF_LDX`=0x01).
    #[must_use]
    pub const fn is_load(self) -> bool {
        self.class() == 0x00 || self.class() == 0x01
    }

    /// Returns `true` if this is a store instruction (`BPF_ST`=0x02 or `BPF_STX`=0x03).
    #[must_use]
    pub const fn is_store(self) -> bool {
        self.class() == 0x02 || self.class() == 0x03
    }

    /// Returns `true` if this is a jump instruction.
    #[must_use]
    pub const fn is_jump(self) -> bool {
        self.class() == 0x05
    }

    /// Returns `true` if this is an exit instruction (`BPF_JMP` | `BPF_EXIT`).
    #[must_use]
    pub const fn is_exit(self) -> bool {
        self.code == 0x95
    }

    /// Returns `true` if this is a call instruction.
    #[must_use]
    pub const fn is_call(self) -> bool {
        self.code == 0x85
    }
}

// ─── VerifierConfig ───────────────────────────────────────────────────────────

/// Configuration for the eBPF verifier.
#[derive(Debug, Clone)]
pub struct VerifierConfig {
    /// Maximum number of instructions allowed in the program.
    pub max_insns: usize,
    /// Maximum number of states to explore (prevents exponential blowup).
    pub max_states: usize,
    /// Allow null pointer arithmetic (relaxed checking).
    pub allow_null_ptr_arith: bool,
    /// Maximum back-edge count (loop bound approximation).
    pub max_back_edges: usize,
}

impl Default for VerifierConfig {
    fn default() -> Self {
        Self {
            max_insns: 1_000_000,
            max_states: 16384,
            allow_null_ptr_arith: false,
            max_back_edges: 16,
        }
    }
}

// ─── VerificationResult ───────────────────────────────────────────────────────

/// The result of running the verifier over a program.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationResult {
    /// `true` if the program passed all checks.
    pub accepted: bool,
    /// All violations detected (empty if accepted with no warnings).
    pub violations: Vec<SafetyViolation>,
    /// Number of instructions analysed.
    pub insns_checked: usize,
    /// Number of abstract states explored.
    pub states_explored: usize,
}

impl VerificationResult {
    #[must_use]
    pub fn errors(&self) -> Vec<&SafetyViolation> {
        self.violations
            .iter()
            .filter(|v| v.severity == ViolationSeverity::Error)
            .collect()
    }

    #[must_use]
    pub fn warnings(&self) -> Vec<&SafetyViolation> {
        self.violations
            .iter()
            .filter(|v| v.severity == ViolationSeverity::Warning)
            .collect()
    }
}

impl fmt::Display for VerificationResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "VerificationResult: accepted={} violations={} insns_checked={} states={}",
            self.accepted,
            self.violations.len(),
            self.insns_checked,
            self.states_explored,
        )
    }
}

// ─── BpfVerifier ──────────────────────────────────────────────────────────────

/// Main eBPF program verifier.
///
/// Performs abstract-interpretation over the program's control flow graph.
/// The verifier tracks the type of each register at every program point
/// and reports safety violations.
pub struct BpfVerifier {
    config: VerifierConfig,
}

impl BpfVerifier {
    /// Create a verifier with default configuration.
    #[must_use]
    pub fn new() -> Self {
        Self {
            config: VerifierConfig::default(),
        }
    }

    /// Create a verifier with custom configuration.
    #[must_use]
    pub const fn with_config(config: VerifierConfig) -> Self {
        Self { config }
    }

    /// Verify a slice of eBPF instructions.
    ///
    /// Returns a [`VerificationResult`] indicating whether the program is safe.
    fn check_program_size(
        &self,
        insns: &[EbpfInsn],
        violations: &mut Vec<SafetyViolation>,
    ) -> bool {
        if insns.is_empty() {
            violations.push(SafetyViolation::error(0, "empty program"));
            return true;
        }
        if insns.len() > self.config.max_insns {
            violations.push(SafetyViolation::error(
                0,
                format!(
                    "program too long: {} > {} instructions",
                    insns.len(),
                    self.config.max_insns
                ),
            ));
            return true;
        }
        false
    }

    #[must_use]
    pub fn verify(&self, insns: &[EbpfInsn]) -> VerificationResult {
        let mut violations = Vec::new();
        let mut states_explored = 0usize;

        if self.check_program_size(insns, &mut violations) {
            let insns_checked = insns.len();
            return VerificationResult {
                accepted: false,
                violations,
                insns_checked,
                states_explored: 0,
            };
        }

        // Work-list DFS: (instruction_index, state)
        let mut worklist: Vec<(usize, VerificationState)> = Vec::new();
        worklist.push((0, VerificationState::entry()));

        // Track visited (pc, state_hash) to detect already-explored states.
        let mut visited_pcs: HashMap<usize, u32> = HashMap::new();
        let mut back_edge_count: HashMap<usize, usize> = HashMap::new();

        while let Some((pc, mut state)) = worklist.pop() {
            if pc >= insns.len() {
                violations.push(SafetyViolation::error(
                    pc,
                    "control flow falls off the end of the program",
                ));
                continue;
            }

            states_explored += 1;
            if states_explored > self.config.max_states {
                violations.push(SafetyViolation::error(
                    pc,
                    format!(
                        "state explosion: explored {} states (limit {})",
                        states_explored, self.config.max_states
                    ),
                ));
                break;
            }

            // Simple back-edge detection.
            let back = back_edge_count.entry(pc).or_insert(0);
            *back += 1;
            if *back > self.config.max_back_edges {
                violations.push(SafetyViolation::warning(
                    pc,
                    format!("back-edge count {back} exceeds limit; truncating loop analysis"),
                ));
                continue;
            }

            let insn = insns[pc];
            Self::check_insn(pc, insn, &mut state, &mut violations);

            if insn.is_exit() {
                // Validate that R0 holds a scalar return value.
                if matches!(state.regs[0], RegisterType::Uninitialised) {
                    violations.push(SafetyViolation::error(
                        pc,
                        "exit with uninitialised R0",
                    ));
                }
                let key = state_hash_key(&state);
                if visited_pcs.get(&pc) == Some(&key) {
                    continue;
                }
                visited_pcs.insert(pc, key);
                continue;
            }

            if insn.is_jump() {
                let fall_through = pc + 1;
                let branch_target = usize::try_from(i64::try_from(pc).unwrap_or(i64::MAX) + 1 + i64::from(insn.off)).unwrap_or(usize::MAX);

                // For unconditional jumps (JA=0x05, CALL=0x85, EXIT=0x95) there is no
                // fall-through path — pushing it would explore dead/unreachable code.
                let is_unconditional = insn.code == 0x05 || insn.code == 0x85 || insn.code == 0x95;

                if !is_unconditional && fall_through < insns.len() {
                    worklist.push((fall_through, state.clone()));
                }
                if insn.code == 0x05 {
                    // JA (unconditional) — only branch target.
                    if branch_target < insns.len() {
                        worklist.push((branch_target, state));
                    }
                } else if !is_unconditional && branch_target < insns.len() {
                    worklist.push((branch_target, state));
                }
            } else {
                worklist.push((pc + 1, state));
            }
        }

        let errors = violations
            .iter()
            .any(|v| v.severity == ViolationSeverity::Error);

        VerificationResult {
            accepted: !errors,
            violations,
            insns_checked: insns.len(),
            states_explored,
        }
    }

    /// Check a single instruction and update state.
    fn check_insn(
        pc: usize,
        insn: EbpfInsn,
        state: &mut VerificationState,
        violations: &mut Vec<SafetyViolation>,
    ) {
        let dst = insn.dst as usize;
        let src = insn.src as usize;

        if dst >= BPF_REG_COUNT {
            violations.push(SafetyViolation::error(
                pc,
                format!("invalid dst register R{dst}"),
            ));
            return;
        }
        if src >= BPF_REG_COUNT {
            violations.push(SafetyViolation::error(
                pc,
                format!("invalid src register R{src}"),
            ));
            return;
        }

        // R10 is read-only.
        if dst == BPF_REG_FP && !insn.is_load() {
            violations.push(SafetyViolation::error(
                pc,
                "write to read-only frame pointer R10",
            ));
        }

        match insn.code {
            // MOV64 imm → dst
            0xb7 => {
                state.set_reg(dst, RegisterType::Constant(i64::from(insn.imm)));
            }
            // MOV64 src → dst
            0xbf => {
                let t = state.regs[src].clone();
                state.set_reg(dst, t);
            }
            // ALU64 operations — result is scalar
            0x07 | 0x0f | 0x17 | 0x1f | 0x27 | 0x2f | 0x37 | 0x3f
            | 0x47 | 0x4f | 0x57 | 0x5f | 0x67 | 0x6f | 0x77 | 0x7f
            | 0xa7 | 0xaf => {
                // Arithmetic on pointers is suspicious.
                if state.regs[dst].is_pointer() {
                    violations.push(SafetyViolation::warning(
                        pc,
                        format!("arithmetic on pointer in R{dst}"),
                    ));
                }
                state.set_reg(dst, RegisterType::Scalar);
            }
            // CALL helper
            0x85 => {
                // After a helper call, R0 = return value (unknown/scalar),
                // R1–R5 are clobbered.
                state.set_reg(0, RegisterType::Scalar);
                for r in 1..=5 {
                    state.set_reg(r, RegisterType::Unknown);
                }
            }
            // Memory loads (LDX)
            0x61 | 0x69 | 0x71 | 0x79 => {
                // Check that src holds a valid pointer.
                if !state.regs[src].is_pointer() && !matches!(state.regs[src], RegisterType::Unknown) {
                    violations.push(SafetyViolation::error(
                        pc,
                        format!(
                            "load from non-pointer R{src} ({:?})",
                            state.regs[src]
                        ),
                    ));
                }
                // Null pointer dereference.
                if matches!(state.regs[src], RegisterType::Null) {
                    violations.push(SafetyViolation::error(pc, format!("null pointer dereference R{src}")));
                }
                state.set_reg(dst, RegisterType::Scalar);
            }
            // Memory stores (STX)
            0x63 | 0x6b | 0x73 | 0x7b => {
                if !state.regs[dst].is_pointer() && !matches!(state.regs[dst], RegisterType::Unknown) {
                    violations.push(SafetyViolation::error(
                        pc,
                        format!(
                            "store to non-pointer R{dst} ({:?})",
                            state.regs[dst]
                        ),
                    ));
                }
            }
            // Stack spill (STX MEM with FP as base)
            _ if dst == BPF_REG_FP && insn.is_store() => {
                let t = state.regs[src].clone();
                state.spill(i32::from(insn.off), t);
            }
            // Stack fill (LDX MEM with FP as base)
            _ if src == BPF_REG_FP && insn.is_load() => {
                let t = state.fill(i32::from(insn.off));
                if matches!(t, RegisterType::Uninitialised) {
                    violations.push(SafetyViolation::error(
                        pc,
                        format!("read from uninitialised stack slot fp+{}", insn.off),
                    ));
                }
                state.set_reg(dst, t);
            }
            _ => {}
        }
    }

    /// Quick structural check: verify all jump targets are within bounds
    /// and the program ends with an exit or unconditional jump.
    #[must_use]
    pub fn check_structure(&self, insns: &[EbpfInsn]) -> Vec<SafetyViolation> {
        let mut v = Vec::new();
        let n = insns.len();

        if n == 0 {
            v.push(SafetyViolation::error(0, "empty program"));
            return v;
        }

        let mut has_exit = false;
        for (i, insn) in insns.iter().enumerate() {
            if insn.is_exit() {
                has_exit = true;
            }
            if insn.is_jump() {
                let target = i64::try_from(i).unwrap_or(i64::MAX) + 1 + i64::from(insn.off);
                if target < 0 || usize::try_from(target).unwrap_or(usize::MAX) >= n {
                    v.push(SafetyViolation::error(
                        i,
                        format!("jump target {target} out of range [0, {n})"),
                    ));
                }
            }
        }
        if !has_exit {
            v.push(SafetyViolation::error(n - 1, "program has no exit instruction"));
        }
        v
    }
}

impl Default for BpfVerifier {
    fn default() -> Self {
        Self::new()
    }
}

/// Compute a simple hash key for a state to detect revisits.
fn state_hash_key(state: &VerificationState) -> u32 {
    let mut h: u32 = 0x811C_9DC5;
    for reg in &state.regs {
        let b = format!("{reg:?}");
        for byte in b.bytes() {
            h = h.wrapping_mul(0x0100_0193) ^ u32::from(byte);
        }
    }
    h
}

// ─── Convenience helpers ──────────────────────────────────────────────────────

/// Parse a byte slice into a list of eBPF instructions.
///
/// # Errors
///
/// Returns an error string if the slice length is not a multiple of 8.
///
/// # Panics
///
/// Panics if a chunk cannot be converted to an 8-byte array, which cannot
/// happen when using `chunks_exact(8)`.
pub fn parse_ebpf_program(bytes: &[u8]) -> Result<Vec<EbpfInsn>, String> {
    if !bytes.len().is_multiple_of(8) {
        return Err(format!(
            "program byte length {} is not a multiple of 8",
            bytes.len()
        ));
    }
    Ok(bytes
        .chunks_exact(8)
        .map(|c| EbpfInsn::from_bytes(c.try_into().unwrap()))
        .collect())
}

/// Verify a raw byte slice as an eBPF program.
///
/// Convenience wrapper around [`BpfVerifier::verify`].
#[must_use]
pub fn verify_ebpf_bytes(bytes: &[u8]) -> VerificationResult {
    match parse_ebpf_program(bytes) {
        Ok(insns) => BpfVerifier::new().verify(&insns),
        Err(msg) => VerificationResult {
            accepted: false,
            violations: vec![SafetyViolation::error(0, msg)],
            insns_checked: 0,
            states_explored: 0,
        },
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn mov64_imm(dst: u8, imm: i32) -> EbpfInsn {
        EbpfInsn { code: 0xb7, dst, src: 0, off: 0, imm }
    }

    fn exit() -> EbpfInsn {
        EbpfInsn { code: 0x95, dst: 0, src: 0, off: 0, imm: 0 }
    }

    #[test]
    fn test_minimal_program_accepted() {
        let insns = vec![mov64_imm(0, 0), exit()];
        let r = BpfVerifier::new().verify(&insns);
        assert!(r.accepted, "{r}");
    }

    #[test]
    fn test_empty_program_rejected() {
        let r = BpfVerifier::new().verify(&[]);
        assert!(!r.accepted);
    }

    #[test]
    fn test_write_to_fp_rejected() {
        let insns = vec![
            EbpfInsn { code: 0xb7, dst: 10, src: 0, off: 0, imm: 1 }, // mov r10, 1
            exit(),
        ];
        let r = BpfVerifier::new().verify(&insns);
        assert!(!r.accepted);
    }

    #[test]
    fn test_exit_with_uninit_r0_rejected() {
        let insns = vec![exit()];
        let r = BpfVerifier::new().verify(&insns);
        assert!(!r.accepted);
        assert!(r.violations.iter().any(|v| v.message.contains("uninitialised R0")));
    }

    #[test]
    fn test_structural_check_out_of_range_jump() {
        let insns = vec![
            EbpfInsn { code: 0x05, dst: 0, src: 0, off: 100, imm: 0 }, // ja +100
        ];
        let v = BpfVerifier::new().check_structure(&insns);
        assert!(!v.is_empty());
        assert!(v[0].message.contains("out of range"));
    }

    #[test]
    fn test_register_type_predicates() {
        assert!(RegisterType::FramePointer { offset: -8 }.is_pointer());
        assert!(!RegisterType::Scalar.is_pointer());
        assert!(RegisterType::Scalar.is_numeric());
        assert!(RegisterType::Constant(42).is_numeric());
        assert!(RegisterType::MapValue { map_id: 1, nullable: false }.is_safe_pointer());
        assert!(!RegisterType::MapValue { map_id: 1, nullable: true }.is_safe_pointer());
    }

    #[test]
    fn test_parse_program_bad_length() {
        assert!(parse_ebpf_program(&[0u8; 7]).is_err());
    }

    #[test]
    fn test_state_join() {
        let mut a = VerificationState::entry();
        a.set_reg(2, RegisterType::Constant(10));
        let mut b = VerificationState::entry();
        b.set_reg(2, RegisterType::Constant(20));
        let joined = a.join(&b);
        assert_eq!(joined.regs[2], RegisterType::Scalar);
    }
}
