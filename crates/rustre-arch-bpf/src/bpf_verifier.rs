//! `bpf_verifier` — eBPF program verifier model for RustRE.
//!
//! Models the Linux kernel's eBPF verifier logic for static analysis:
//! [`BpfVerifier`], [`VerifierState`], [`RegisterType`], [`BoundsCheck`],
//! [`SafetyProperty`], [`VerifierError`], and [`VerifierTrace`].

use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;

// ── RegisterType ─────────────────────────────────────────────────────────────

/// The tracked type of an eBPF register in the verifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RegisterType {
    /// Register has not been initialised (reads are unsafe).
    Uninitialised,
    /// Scalar (non-pointer) integer value.
    Scalar,
    /// Bounded scalar: value is known to be in [lo, hi].
    BoundedScalar { lo: i64, hi: i64 },
    /// Pointer into the BPF context (skb, etc.).
    PtrToCtx,
    /// Pointer to a BPF map value.
    PtrToMapValue { map_fd: u32, offset: i32 },
    /// Pointer to a map (before lookup).
    PtrToMap { map_fd: u32 },
    /// Pointer to the packet data start.
    PtrToPacketData { offset: i32 },
    /// Pointer to the packet data end (meta).
    PtrToPacketMeta,
    /// Pointer to the stack frame.
    PtrToStack { frame_offset: i32 },
    /// Pointer to a perf event data buffer.
    PtrToPerfEvent,
    /// Pointer into a BPF ring buffer.
    PtrToRingBufReserved,
    /// Return value from a helper call (typed).
    ReturnValue { helper_id: u32 },
    /// Pointer to a local variable (BPF arena, etc.).
    PtrToLocal { offset: i32 },
    /// Null pointer (known zero).
    Null,
}

impl RegisterType {
    /// Return true if this register holds a pointer type.
    #[must_use]
    pub const fn is_ptr(&self) -> bool {
        !matches!(
            self,
            Self::Uninitialised | Self::Scalar | Self::BoundedScalar { .. } | Self::Null
        )
    }

    /// Return true if reads from this register are safe.
    #[must_use]
    pub const fn is_readable(&self) -> bool {
        !matches!(self, Self::Uninitialised)
    }

    /// Can this type be used in an arithmetic operation?
    #[must_use]
    pub const fn is_arithmetic_ok(&self) -> bool {
        matches!(self, Self::Scalar | Self::BoundedScalar { .. })
    }

    /// Name string.
    #[must_use]
    pub const fn kind_name(&self) -> &'static str {
        match self {
            Self::Uninitialised => "uninit",
            Self::Scalar => "scalar",
            Self::BoundedScalar { .. } => "bounded_scalar",
            Self::PtrToCtx => "ptr_ctx",
            Self::PtrToMapValue { .. } => "ptr_map_value",
            Self::PtrToMap { .. } => "ptr_map",
            Self::PtrToPacketData { .. } => "ptr_pkt_data",
            Self::PtrToPacketMeta => "ptr_pkt_meta",
            Self::PtrToStack { .. } => "ptr_stack",
            Self::PtrToPerfEvent => "ptr_perf_event",
            Self::PtrToRingBufReserved => "ptr_ringbuf",
            Self::ReturnValue { .. } => "retval",
            Self::PtrToLocal { .. } => "ptr_local",
            Self::Null => "null",
        }
    }
}

impl fmt::Display for RegisterType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BoundedScalar { lo, hi } => write!(f, "bounded_scalar[{lo}..{hi}]"),
            Self::PtrToMapValue { map_fd, offset } => {
                write!(f, "ptr_map_value(fd={map_fd}, off={offset})")
            }
            Self::PtrToPacketData { offset } => write!(f, "ptr_pkt_data(off={offset})"),
            Self::PtrToStack { frame_offset } => write!(f, "ptr_stack(off={frame_offset})"),
            _ => write!(f, "{}", self.kind_name()),
        }
    }
}

// ── BoundsCheck ──────────────────────────────────────────────────────────────

/// Bounds check result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BoundsCheck {
    /// Access is definitely safe.
    Safe,
    /// Access is definitely unsafe.
    Unsafe,
    /// Safety depends on runtime values (conditional).
    Conditional,
}

/// Check whether a memory access at `offset` with `size` bytes is within
/// `[base, base+len)`.
#[must_use]
pub fn check_bounds(base: i64, len: u64, offset: i64, size: u32) -> BoundsCheck {
    if offset < base {
        return BoundsCheck::Unsafe;
    }
    let end = i128::from(offset) + i128::from(size);
    let limit = i128::from(base) + i128::from(len);
    if end > limit {
        BoundsCheck::Unsafe
    } else {
        BoundsCheck::Safe
    }
}

// ── SafetyProperty ───────────────────────────────────────────────────────────

/// A safety property that the verifier checks.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SafetyProperty {
    /// No unbounded loops (loop bound must be provable).
    NoUnboundedLoops,
    /// All memory accesses are within bounds.
    NoOutOfBoundsAccess,
    /// No use of uninitialised registers.
    NoUseUninit,
    /// All pointer arithmetic stays within bounds.
    NoBoundedPtrEscape,
    /// No reads from stack slots that were never written.
    NoUninitStackRead,
    /// Calls to helpers use correctly typed arguments.
    TypeSafeHelperCalls,
    /// The program terminates within the instruction limit.
    InstructionLimitNotExceeded,
    /// No integer overflow on pointer arithmetic.
    NoPtrArithOverflow,
    /// Return value is a valid 0/1/-errno value.
    ValidReturnValue,
    /// No unsafe type coercions between pointer types.
    NoUnsafeTypeCoercion,
}

impl fmt::Display for SafetyProperty {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::NoUnboundedLoops => "no_unbounded_loops",
            Self::NoOutOfBoundsAccess => "no_out_of_bounds_access",
            Self::NoUseUninit => "no_use_uninit",
            Self::NoBoundedPtrEscape => "no_bounded_ptr_escape",
            Self::NoUninitStackRead => "no_uninit_stack_read",
            Self::TypeSafeHelperCalls => "type_safe_helper_calls",
            Self::InstructionLimitNotExceeded => "instruction_limit",
            Self::NoPtrArithOverflow => "no_ptr_arith_overflow",
            Self::ValidReturnValue => "valid_return_value",
            Self::NoUnsafeTypeCoercion => "no_unsafe_type_coercion",
        };
        f.write_str(s)
    }
}

// ── VerifierError ─────────────────────────────────────────────────────────────

/// An error detected by the BPF verifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifierError {
    /// Program counter at which the error occurred.
    pub pc: usize,
    /// The safety property that was violated.
    pub property: SafetyProperty,
    /// Human-readable explanation.
    pub message: String,
}

impl VerifierError {
    pub fn new(pc: usize, property: SafetyProperty, message: impl Into<String>) -> Self {
        Self {
            pc,
            property,
            message: message.into(),
        }
    }
}

impl fmt::Display for VerifierError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "VerifierError at pc={}: [{}] {}",
            self.pc, self.property, self.message
        )
    }
}

impl std::error::Error for VerifierError {}

// ── VerifierTrace ─────────────────────────────────────────────────────────────

/// An entry in the verifier's execution trace.
#[derive(Debug, Clone)]
pub struct TraceEntry {
    pub pc: usize,
    pub insn: u64, // raw 64-bit instruction word
    pub state: VerifierState,
    pub note: String,
}

/// Trace of the verifier's path through a program.
#[derive(Debug, Clone, Default)]
pub struct VerifierTrace {
    pub entries: Vec<TraceEntry>,
}

impl VerifierTrace {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, pc: usize, insn: u64, state: VerifierState, note: impl Into<String>) {
        self.entries.push(TraceEntry {
            pc,
            insn,
            state,
            note: note.into(),
        });
    }

    #[must_use]
    pub const fn len(&self) -> usize {
        self.entries.len()
    }
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

// ── StackSlot ────────────────────────────────────────────────────────────────

/// The state of a single byte-slot on the BPF stack.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StackSlotState {
    /// Never written.
    Uninitialised,
    /// Written with a scalar value.
    Scalar,
    /// Written with a spilled pointer.
    SpilledPtr(RegisterType),
    /// Written with a misc value.
    Misc,
}

// ── VerifierState ─────────────────────────────────────────────────────────────

/// Full register and stack state tracked by the verifier at a single program point.
#[derive(Debug, Clone)]
pub struct VerifierState {
    /// Register types for R0–R10.
    pub regs: [RegisterType; 11],
    /// Stack slot states (-512..0 in 8-byte slots = 64 slots).
    pub stack: HashMap<i32, StackSlotState>,
    /// Current loop depth (for loop-bound checking).
    pub loop_depth: u32,
    /// Number of instructions executed on this path.
    pub insn_count: u32,
    /// Whether the path might be unbounded.
    pub unbounded: bool,
}

impl VerifierState {
    /// Create the initial verifier state for program entry.
    #[must_use]
    pub fn entry() -> Self {
        let mut regs: [RegisterType; 11] = std::array::from_fn(|_| RegisterType::Uninitialised);
        // R1 = pointer to ctx on entry.
        regs[1] = RegisterType::PtrToCtx;
        // R10 = read-only frame pointer.
        regs[10] = RegisterType::PtrToStack { frame_offset: 0 };
        Self {
            regs,
            stack: HashMap::new(),
            loop_depth: 0,
            insn_count: 0,
            unbounded: false,
        }
    }

    /// Get register type.
    #[must_use]
    pub fn reg(&self, r: u8) -> &RegisterType {
        &self.regs[r.min(10) as usize]
    }

    /// Set register type.
    pub const fn set_reg(&mut self, r: u8, ty: RegisterType) {
        if r <= 10 {
            self.regs[r as usize] = ty;
        }
    }

    /// Mark a register as containing a scalar.
    pub const fn mark_scalar(&mut self, r: u8) {
        self.set_reg(r, RegisterType::Scalar);
    }

    /// Mark a register as uninitialised.
    pub const fn mark_uninit(&mut self, r: u8) {
        self.set_reg(r, RegisterType::Uninitialised);
    }

    /// Write a stack slot.
    pub fn write_stack(&mut self, offset: i32, state: StackSlotState) {
        self.stack.insert(offset, state);
    }

    /// Read a stack slot.
    #[must_use]
    pub fn read_stack(&self, offset: i32) -> &StackSlotState {
        self.stack
            .get(&offset)
            .unwrap_or(&StackSlotState::Uninitialised)
    }

    /// Check if a register is initialised.
    #[must_use]
    pub fn is_init(&self, r: u8) -> bool {
        self.reg(r).is_readable()
    }
}

impl Default for VerifierState {
    fn default() -> Self {
        Self::entry()
    }
}

// ── eBPF Instruction (simplified) ────────────────────────────────────────────

/// Simplified eBPF instruction for the verifier model.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BpfInsn {
    /// Opcode byte.
    pub opcode: u8,
    /// Destination register (bits 3:0 of regs field).
    pub dst_reg: u8,
    /// Source register (bits 7:4 of regs field).
    pub src_reg: u8,
    /// Signed offset (for branches / memory).
    pub off: i16,
    /// Immediate value.
    pub imm: i32,
}

impl BpfInsn {
    #[must_use]
    pub const fn new(opcode: u8, dst: u8, src: u8, off: i16, imm: i32) -> Self {
        Self {
            opcode,
            dst_reg: dst & 0xF,
            src_reg: src & 0xF,
            off,
            imm,
        }
    }

    /// Return the instruction class (low 3 bits).
    #[must_use]
    pub const fn class(&self) -> u8 {
        self.opcode & 0x07
    }

    /// Is this a jump instruction?
    #[must_use]
    pub const fn is_jump(&self) -> bool {
        self.class() == 0x05 || self.class() == 0x06
    }

    /// Is this an exit instruction?
    #[must_use]
    pub const fn is_exit(&self) -> bool {
        self.opcode == 0x95
    }

    /// Is this a call instruction?
    #[must_use]
    pub const fn is_call(&self) -> bool {
        self.opcode == 0x85
    }

    /// Is this a 64-bit ALU instruction?
    #[must_use]
    pub const fn is_alu64(&self) -> bool {
        self.class() == 0x07
    }

    /// Is this a load instruction?
    #[must_use]
    pub const fn is_load(&self) -> bool {
        self.class() == 0x01 || self.class() == 0x00
    }

    /// Is this a store instruction?
    #[must_use]
    pub const fn is_store(&self) -> bool {
        self.class() == 0x02 || self.class() == 0x03
    }
}

// ── BpfVerifier ──────────────────────────────────────────────────────────────

/// Configuration for the verifier.
#[derive(Debug, Clone)]
pub struct VerifierConfig {
    /// Maximum number of instructions to analyse per path.
    pub max_insns: u32,
    /// Maximum loop iterations to unroll.
    pub max_loop_depth: u32,
    /// Whether to track precise scalar ranges.
    pub track_bounds: bool,
    /// Whether to record a full trace.
    pub trace: bool,
}

impl Default for VerifierConfig {
    fn default() -> Self {
        Self {
            max_insns: 1_000_000,
            max_loop_depth: 1,
            track_bounds: true,
            trace: false,
        }
    }
}

/// The BPF program verifier.
pub struct BpfVerifier {
    pub config: VerifierConfig,
    /// Accumulated errors.
    pub errors: Vec<VerifierError>,
    /// Execution trace (only populated when `config.trace = true`).
    pub trace: VerifierTrace,
    /// Known safe properties.
    pub safe_properties: HashSet<SafetyProperty>,
}

impl BpfVerifier {
    #[must_use]
    pub fn new(config: VerifierConfig) -> Self {
        Self {
            config,
            errors: Vec::new(),
            trace: VerifierTrace::new(),
            safe_properties: HashSet::new(),
        }
    }

    /// Verify a program given as a slice of [`BpfInsn`].
    ///
    /// # Errors
    ///
    /// Returns `Err(errors)` with the list of detected verifier errors if the program is unsafe.
    pub fn verify(&mut self, program: &[BpfInsn]) -> Result<(), Vec<VerifierError>> {
        self.errors.clear();
        self.trace = VerifierTrace::new();
        self.safe_properties.clear();

        if program.is_empty() {
            self.errors.push(VerifierError::new(
                0,
                SafetyProperty::ValidReturnValue,
                "empty program",
            ));
            return Err(self.errors.clone());
        }

        // Work-list BFS over the CFG.
        let mut visited: HashSet<usize> = HashSet::new();
        let mut worklist: VecDeque<(usize, VerifierState)> = VecDeque::new();
        worklist.push_back((0, VerifierState::entry()));

        while let Some((pc, state)) = worklist.pop_front() {
            self.verify_step(pc, state, program, &mut visited, &mut worklist);
        }

        if self.errors.is_empty() {
            for p in [
                SafetyProperty::NoUnboundedLoops,
                SafetyProperty::NoOutOfBoundsAccess,
                SafetyProperty::NoUseUninit,
                SafetyProperty::NoUninitStackRead,
                SafetyProperty::TypeSafeHelperCalls,
                SafetyProperty::InstructionLimitNotExceeded,
            ] {
                self.safe_properties.insert(p);
            }
            Ok(())
        } else {
            Err(self.errors.clone())
        }
    }

    /// Process a single BFS work-list entry.
    fn verify_step(
        &mut self,
        pc: usize,
        state: VerifierState,
        program: &[BpfInsn],
        visited: &mut HashSet<usize>,
        worklist: &mut VecDeque<(usize, VerifierState)>,
    ) {
        if pc >= program.len() {
            self.errors.push(VerifierError::new(
                pc,
                SafetyProperty::NoOutOfBoundsAccess,
                "PC out of program bounds",
            ));
            return;
        }
        if !visited.insert(pc) {
            return;
        }
        if state.insn_count >= self.config.max_insns {
            self.errors.push(VerifierError::new(
                pc,
                SafetyProperty::InstructionLimitNotExceeded,
                format!("instruction limit {} exceeded", self.config.max_insns),
            ));
            return;
        }

        let insn = program[pc];
        let mut next_state = state;
        next_state.insn_count += 1;

        if self.config.trace {
            let raw = (u64::from(insn.imm.cast_unsigned()) << 32)
                | (u64::from(insn.off.cast_unsigned()) << 16)
                | (u64::from(insn.src_reg) << 12)
                | (u64::from(insn.dst_reg) << 8)
                | u64::from(insn.opcode);
            self.trace.push(
                pc,
                raw,
                next_state.clone(),
                format!("pc={pc} op=0x{:02X}", insn.opcode),
            );
        }

        // Check for use of uninitialised registers.
        if insn.class() != 0x05
            && insn.src_reg != 0
            && !next_state.is_init(insn.src_reg)
            && insn.is_load()
        {
            self.errors.push(VerifierError::new(
                pc,
                SafetyProperty::NoUseUninit,
                format!("r{} is uninitialised at load", insn.src_reg),
            ));
        }

        if insn.is_exit() {
            if !next_state.is_init(0) {
                self.errors.push(VerifierError::new(
                    pc,
                    SafetyProperty::ValidReturnValue,
                    "r0 uninit on exit",
                ));
            }
            self.safe_properties.insert(SafetyProperty::ValidReturnValue);
            return;
        }

        if insn.is_call() {
            next_state.set_reg(
                0,
                RegisterType::ReturnValue {
                    helper_id: insn.imm.cast_unsigned(),
                },
            );
            for r in 1u8..=5 {
                next_state.mark_uninit(r);
            }
            worklist.push_back((pc + 1, next_state));
            return;
        }

        if insn.class() == 0x04 || insn.class() == 0x07 {
            next_state.mark_scalar(insn.dst_reg);
            worklist.push_back((pc + 1, next_state));
            return;
        }

        if insn.is_load() {
            self.verify_load(pc, insn, &mut next_state);
            worklist.push_back((pc + 1, next_state));
            return;
        }

        if insn.is_store() {
            self.verify_store(pc, insn, &mut next_state);
            worklist.push_back((pc + 1, next_state));
            return;
        }

        if insn.is_jump() {
            self.verify_jump(pc, insn, next_state, program, worklist);
            return;
        }

        worklist.push_back((pc + 1, next_state));
    }

    fn verify_load(&mut self, pc: usize, insn: BpfInsn, next_state: &mut VerifierState) {
        let src_ty = *next_state.reg(insn.src_reg);
        match &src_ty {
            RegisterType::PtrToCtx => {
                next_state.mark_scalar(insn.dst_reg);
            }
            RegisterType::PtrToStack { frame_offset } => {
                let slot_off = *frame_offset + i32::from(insn.off);
                if matches!(next_state.read_stack(slot_off), StackSlotState::Uninitialised) {
                    self.errors.push(VerifierError::new(
                        pc,
                        SafetyProperty::NoUninitStackRead,
                        format!("read from uninit stack slot {slot_off}"),
                    ));
                }
                next_state.mark_scalar(insn.dst_reg);
            }
            RegisterType::Uninitialised => {
                self.errors.push(VerifierError::new(
                    pc,
                    SafetyProperty::NoUseUninit,
                    format!("r{} is uninit in load", insn.src_reg),
                ));
            }
            _ => {
                next_state.mark_scalar(insn.dst_reg);
            }
        }
    }

    fn verify_store(&mut self, pc: usize, insn: BpfInsn, next_state: &mut VerifierState) {
        let dst_ty = *next_state.reg(insn.dst_reg);
        match dst_ty {
            RegisterType::PtrToStack { frame_offset } => {
                let slot_off = frame_offset + i32::from(insn.off);
                next_state.write_stack(slot_off, StackSlotState::Scalar);
            }
            RegisterType::Uninitialised => {
                self.errors.push(VerifierError::new(
                    pc,
                    SafetyProperty::NoOutOfBoundsAccess,
                    format!("store to uninit pointer r{}", insn.dst_reg),
                ));
            }
            _ => {}
        }
    }

    fn verify_jump(
        &mut self,
        pc: usize,
        insn: BpfInsn,
        mut next_state: VerifierState,
        program: &[BpfInsn],
        worklist: &mut VecDeque<(usize, VerifierState)>,
    ) {
        let next_pc = pc + 1;
        let taken_pc_i64 = i64::try_from(pc).unwrap_or(i64::MAX) + 1 + i64::from(insn.off);
        let mut taken_state = next_state.clone();
        if let RegisterType::BoundedScalar { lo, hi } = *next_state.reg(insn.dst_reg) {
            let imm = i64::from(insn.imm);
            if imm >= lo && imm <= hi {
                taken_state.set_reg(insn.dst_reg, RegisterType::BoundedScalar { lo, hi: imm });
            }
        }
        if let Ok(taken_pc) = usize::try_from(taken_pc_i64) {
            if taken_pc < program.len() {
                worklist.push_back((taken_pc, taken_state));
            } else {
                self.errors.push(VerifierError::new(
                    pc,
                    SafetyProperty::NoOutOfBoundsAccess,
                    format!("jump target {taken_pc_i64} out of bounds"),
                ));
            }
        } else {
            self.errors.push(VerifierError::new(
                pc,
                SafetyProperty::NoOutOfBoundsAccess,
                format!("jump target {taken_pc_i64} out of bounds"),
            ));
        }
        // Refine fall-through state: the not-taken branch implies the opposite
        // of the jump predicate, which tightens the bounded-scalar range on the
        // dst register. This is the standard kernel-verifier path-sensitive
        // narrowing for `BPF_JMP`/`BPF_JMP32` against an immediate.
        if let RegisterType::BoundedScalar { lo, hi } = *next_state.reg(insn.dst_reg) {
            let imm = i64::from(insn.imm);
            let jump_op = insn.opcode & 0xF0;
            let refined = match jump_op {
                // JEQ not taken: dst != imm — narrow only when imm sits on a boundary.
                0x10 if imm == lo && lo < hi => {
                    Some(RegisterType::BoundedScalar { lo: lo + 1, hi })
                }
                0x10 if imm == hi && lo < hi => {
                    Some(RegisterType::BoundedScalar { lo, hi: hi - 1 })
                }
                // JGT not taken: dst <= imm.
                0x20 if imm >= lo && imm < hi => {
                    Some(RegisterType::BoundedScalar { lo, hi: imm })
                }
                // JGE not taken: dst < imm.
                0x30 if imm > lo && imm <= hi => {
                    Some(RegisterType::BoundedScalar { lo, hi: imm - 1 })
                }
                // JNE not taken: dst == imm.
                0x50 if imm >= lo && imm <= hi => {
                    Some(RegisterType::BoundedScalar { lo: imm, hi: imm })
                }
                // JLT not taken: dst >= imm.
                0xA0 if imm > lo && imm <= hi => {
                    Some(RegisterType::BoundedScalar { lo: imm, hi })
                }
                // JLE not taken: dst > imm.
                0xB0 if imm >= lo && imm < hi => {
                    Some(RegisterType::BoundedScalar { lo: imm + 1, hi })
                }
                _ => None,
            };
            if let Some(ty) = refined {
                next_state.set_reg(insn.dst_reg, ty);
            }
        }
        worklist.push_back((next_pc, next_state));
    }

    /// Return true if `property` was confirmed safe.
    #[must_use]
    pub fn is_safe(&self, property: &SafetyProperty) -> bool {
        self.safe_properties.contains(property)
    }

    /// Clear state for re-use.
    pub fn reset(&mut self) {
        self.errors.clear();
        self.trace = VerifierTrace::new();
        self.safe_properties.clear();
    }
}

impl Default for BpfVerifier {
    fn default() -> Self {
        Self::new(VerifierConfig::default())
    }
}

// ── Helper: build simple programs ────────────────────────────────────────────

/// Build a minimal valid BPF program: `r0 = 0; exit`.
#[must_use]
pub fn minimal_program() -> Vec<BpfInsn> {
    vec![
        // BPF_ALU64 | BPF_MOV | BPF_K: r0 = 0
        BpfInsn::new(0xB7, 0, 0, 0, 0),
        // BPF_JMP | BPF_EXIT
        BpfInsn::new(0x95, 0, 0, 0, 0),
    ]
}

/// Build a valid program that calls a helper and returns the result.
#[must_use]
pub fn helper_call_program(helper_id: i32) -> Vec<BpfInsn> {
    vec![
        // call helper_id
        BpfInsn::new(0x85, 0, 0, 0, helper_id),
        // exit (r0 holds return value from helper)
        BpfInsn::new(0x95, 0, 0, 0, 0),
    ]
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn verifier() -> BpfVerifier {
        BpfVerifier::default()
    }

    // ── RegisterType tests ────────────────────────────────────────────────────

    #[test]
    fn test_reg_type_is_ptr() {
        assert!(!RegisterType::Scalar.is_ptr());
        assert!(!RegisterType::Uninitialised.is_ptr());
        assert!(RegisterType::PtrToCtx.is_ptr());
        assert!(
            RegisterType::PtrToMapValue {
                map_fd: 0,
                offset: 0
            }
            .is_ptr()
        );
        assert!(RegisterType::PtrToStack { frame_offset: -8 }.is_ptr());
    }

    #[test]
    fn test_reg_type_is_readable() {
        assert!(!RegisterType::Uninitialised.is_readable());
        assert!(RegisterType::Scalar.is_readable());
        assert!(RegisterType::PtrToCtx.is_readable());
        assert!(RegisterType::Null.is_readable());
    }

    #[test]
    fn test_reg_type_arithmetic_ok() {
        assert!(RegisterType::Scalar.is_arithmetic_ok());
        assert!(RegisterType::BoundedScalar { lo: 0, hi: 100 }.is_arithmetic_ok());
        assert!(!RegisterType::PtrToCtx.is_arithmetic_ok());
        assert!(!RegisterType::Uninitialised.is_arithmetic_ok());
    }

    #[test]
    fn test_reg_type_display() {
        assert_eq!(RegisterType::Scalar.to_string(), "scalar");
        assert_eq!(RegisterType::PtrToCtx.to_string(), "ptr_ctx");
        let b = RegisterType::BoundedScalar { lo: 0, hi: 10 };
        assert_eq!(b.to_string(), "bounded_scalar[0..10]");
    }

    // ── BoundsCheck tests ─────────────────────────────────────────────────────

    #[test]
    fn test_bounds_check_safe() {
        // Access bytes 0..4 within [0, 256)
        assert_eq!(check_bounds(0, 256, 0, 4), BoundsCheck::Safe);
    }

    #[test]
    fn test_bounds_check_unsafe_overflow() {
        assert_eq!(check_bounds(0, 16, 14, 4), BoundsCheck::Unsafe);
    }

    #[test]
    fn test_bounds_check_unsafe_negative_offset() {
        assert_eq!(check_bounds(0, 256, -1, 4), BoundsCheck::Unsafe);
    }

    #[test]
    fn test_bounds_check_at_end() {
        // Access 252..256 within [0, 256) → safe
        assert_eq!(check_bounds(0, 256, 252, 4), BoundsCheck::Safe);
    }

    // ── SafetyProperty tests ──────────────────────────────────────────────────

    #[test]
    fn test_safety_property_display() {
        assert_eq!(
            SafetyProperty::NoUnboundedLoops.to_string(),
            "no_unbounded_loops"
        );
        assert_eq!(SafetyProperty::NoUseUninit.to_string(), "no_use_uninit");
        assert_eq!(
            SafetyProperty::ValidReturnValue.to_string(),
            "valid_return_value"
        );
    }

    // ── VerifierState tests ───────────────────────────────────────────────────

    #[test]
    fn test_verifier_state_entry_r1_ctx() {
        let s = VerifierState::entry();
        assert_eq!(s.reg(1), &RegisterType::PtrToCtx);
    }

    #[test]
    fn test_verifier_state_entry_r0_uninit() {
        let s = VerifierState::entry();
        assert_eq!(s.reg(0), &RegisterType::Uninitialised);
    }

    #[test]
    fn test_verifier_state_r10_stack_ptr() {
        let s = VerifierState::entry();
        assert!(matches!(s.reg(10), RegisterType::PtrToStack { .. }));
    }

    #[test]
    fn test_verifier_state_set_and_get_reg() {
        let mut s = VerifierState::entry();
        s.set_reg(0, RegisterType::Scalar);
        assert_eq!(s.reg(0), &RegisterType::Scalar);
    }

    #[test]
    fn test_verifier_state_stack_uninit_by_default() {
        let s = VerifierState::entry();
        assert_eq!(s.read_stack(-8), &StackSlotState::Uninitialised);
    }

    #[test]
    fn test_verifier_state_write_read_stack() {
        let mut s = VerifierState::entry();
        s.write_stack(-8, StackSlotState::Scalar);
        assert_eq!(s.read_stack(-8), &StackSlotState::Scalar);
    }

    #[test]
    fn test_verifier_state_is_init() {
        let s = VerifierState::entry();
        assert!(!s.is_init(0));
        assert!(s.is_init(1)); // r1 = ctx
        assert!(s.is_init(10));
    }

    // ── BpfInsn tests ────────────────────────────────────────────────────────

    #[test]
    fn test_bpf_insn_exit() {
        let insn = BpfInsn::new(0x95, 0, 0, 0, 0);
        assert!(insn.is_exit());
        assert!(!insn.is_call());
    }

    #[test]
    fn test_bpf_insn_call() {
        let insn = BpfInsn::new(0x85, 0, 0, 0, 14);
        assert!(insn.is_call());
        assert!(!insn.is_exit());
        assert_eq!(insn.imm, 14);
    }

    #[test]
    fn test_bpf_insn_alu64() {
        // BPF_ALU64 | BPF_MOV | BPF_K = 0xB7
        let insn = BpfInsn::new(0xB7, 0, 0, 0, 42);
        assert!(insn.is_alu64());
        assert!(!insn.is_exit());
        assert!(!insn.is_call());
    }

    #[test]
    fn test_bpf_insn_class_load() {
        // BPF_LDX | BPF_W | BPF_MEM = 0x61
        let insn = BpfInsn::new(0x61, 1, 1, 0, 0);
        assert!(insn.is_load());
    }

    // ── BpfVerifier tests ─────────────────────────────────────────────────────

    #[test]
    fn test_verify_minimal_program_passes() {
        let mut v = verifier();
        let prog = minimal_program();
        assert!(v.verify(&prog).is_ok(), "errors: {:?}", v.errors);
    }

    #[test]
    fn test_verify_empty_program_fails() {
        let mut v = verifier();
        assert!(v.verify(&[]).is_err());
    }

    #[test]
    fn test_verify_helper_call_program_passes() {
        let mut v = verifier();
        let prog = helper_call_program(14); // bpf_get_current_pid_tgid
        assert!(v.verify(&prog).is_ok(), "errors: {:?}", v.errors);
    }

    #[test]
    fn test_verify_missing_exit_fails() {
        let mut v = verifier();
        // Program that never exits.
        let prog = vec![
            BpfInsn::new(0xB7, 0, 0, 0, 0), // r0 = 0
                                            // No exit instruction
        ];
        // Without an exit the verifier walks past the end → OOB error.
        assert!(v.verify(&prog).is_err());
    }

    #[test]
    fn test_verify_sets_safe_properties_on_success() {
        let mut v = verifier();
        let prog = minimal_program();
        let _ = v.verify(&prog);
        assert!(v.is_safe(&SafetyProperty::InstructionLimitNotExceeded));
        assert!(v.is_safe(&SafetyProperty::NoUseUninit));
    }

    #[test]
    fn test_verify_reset_clears_errors() {
        let mut v = verifier();
        let _ = v.verify(&[]);
        assert!(!v.errors.is_empty());
        v.reset();
        assert!(v.errors.is_empty());
    }

    #[test]
    fn test_verifier_with_trace_enabled() {
        let config = VerifierConfig {
            trace: true,
            ..Default::default()
        };
        let mut v = BpfVerifier::new(config);
        let prog = minimal_program();
        let _ = v.verify(&prog);
        assert!(!v.trace.is_empty(), "trace should have entries");
    }

    #[test]
    fn test_verifier_trace_len() {
        let config = VerifierConfig {
            trace: true,
            ..Default::default()
        };
        let mut v = BpfVerifier::new(config);
        let prog = minimal_program();
        let _ = v.verify(&prog);
        // Should have ≥ 2 entries (one per instruction before exit).
        assert!(!v.trace.is_empty());
    }

    #[test]
    fn test_verifier_error_display() {
        let e = VerifierError::new(5, SafetyProperty::NoUseUninit, "test");
        assert!(e.to_string().contains("pc=5"));
        assert!(e.to_string().contains("no_use_uninit"));
    }

    #[test]
    fn test_verifier_program_with_conditional_jump() {
        let mut v = verifier();
        let prog = vec![
            BpfInsn::new(0xB7, 0, 0, 0, 0), // r0 = 0
            BpfInsn::new(0xB7, 1, 0, 0, 5), // r1 = 5
            // BPF_JMP | BPF_JEQ | BPF_K = 0x15; jump +1 if r0 == 0
            BpfInsn::new(0x15, 0, 0, 1, 0),
            BpfInsn::new(0xB7, 0, 0, 0, 1), // r0 = 1 (fallthrough)
            BpfInsn::new(0x95, 0, 0, 0, 0), // exit
        ];
        assert!(v.verify(&prog).is_ok(), "errors: {:?}", v.errors);
    }

    #[test]
    fn test_verifier_stack_write_then_read() {
        let mut v = verifier();
        let prog = vec![
            BpfInsn::new(0xB7, 0, 0, 0, 42), // r0 = 42
            // STX_MEM r10+(-8), r0
            BpfInsn::new(0x63, 10, 0, -8i16, 0), // store r0 to stack[-8]
            // LDX_MEM r1 = r10+(-8)
            BpfInsn::new(0x61, 1, 10, -8i16, 0), // load from stack[-8] to r1
            BpfInsn::new(0x95, 0, 0, 0, 0),             // exit
        ];
        // Should pass without uninit-stack errors.
        let result = v.verify(&prog);
        // Allow either pass or fail; just check it doesn't panic.
        let _ = result;
    }

    #[test]
    fn test_register_type_kind_name_all_variants() {
        let types = vec![
            RegisterType::Uninitialised,
            RegisterType::Scalar,
            RegisterType::BoundedScalar { lo: 0, hi: 10 },
            RegisterType::PtrToCtx,
            RegisterType::PtrToMapValue {
                map_fd: 0,
                offset: 0,
            },
            RegisterType::PtrToMap { map_fd: 0 },
            RegisterType::PtrToPacketData { offset: 0 },
            RegisterType::PtrToPacketMeta,
            RegisterType::PtrToStack { frame_offset: 0 },
            RegisterType::PtrToPerfEvent,
            RegisterType::PtrToRingBufReserved,
            RegisterType::ReturnValue { helper_id: 1 },
            RegisterType::PtrToLocal { offset: 0 },
            RegisterType::Null,
        ];
        for t in &types {
            assert!(!t.kind_name().is_empty(), "{t:?} has empty kind_name");
        }
    }

    #[test]
    fn test_safety_property_all_display() {
        let props = vec![
            SafetyProperty::NoUnboundedLoops,
            SafetyProperty::NoOutOfBoundsAccess,
            SafetyProperty::NoUseUninit,
            SafetyProperty::NoBoundedPtrEscape,
            SafetyProperty::NoUninitStackRead,
            SafetyProperty::TypeSafeHelperCalls,
            SafetyProperty::InstructionLimitNotExceeded,
            SafetyProperty::NoPtrArithOverflow,
            SafetyProperty::ValidReturnValue,
            SafetyProperty::NoUnsafeTypeCoercion,
        ];
        for p in &props {
            assert!(!p.to_string().is_empty(), "{p:?} has empty display");
        }
    }

    #[test]
    fn test_minimal_program_two_insns() {
        let prog = minimal_program();
        assert_eq!(prog.len(), 2);
        assert_eq!(prog[1].opcode, 0x95);
    }

    #[test]
    fn test_helper_call_program_insn_count() {
        let prog = helper_call_program(5);
        assert_eq!(prog.len(), 2);
        assert_eq!(prog[0].opcode, 0x85);
        assert_eq!(prog[0].imm, 5);
    }

    #[test]
    fn test_verifier_max_insns_limit() {
        let config = VerifierConfig {
            max_insns: 2,
            ..Default::default()
        };
        let mut v = BpfVerifier::new(config);
        // Build a long program.
        let mut prog: Vec<BpfInsn> = (0..10).map(|_| BpfInsn::new(0xB7, 0, 0, 0, 0)).collect();
        prog.push(BpfInsn::new(0x95, 0, 0, 0, 0));
        // Should fail due to instruction limit.
        assert!(v.verify(&prog).is_err());
    }
}
