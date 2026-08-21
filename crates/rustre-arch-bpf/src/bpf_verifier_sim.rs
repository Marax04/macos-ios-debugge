//! BPF kernel verifier simulation.
//!
//! This module simulates the type-tracking and safety-checking logic of the
//! Linux kernel's BPF verifier (`kernel/bpf/verifier.c`).  It does **not**
//! reproduce the full verifier (taint analysis, precise state pruning, etc.)
//! but does model:
//!
//! * Per-register type states (`NOT_INIT`, `SCALAR_VALUE`, `PTR_TO_*`).
//! * Pointer arithmetic legality rules.
//! * Map value dereferencing.
//! * Packet data access bounds (`PTR_TO_PACKET` vs `PTR_TO_PACKET_END`).
//! * Stack slot tracking (spill/fill of scalars and pointers).
//! * Helper call argument type constraints.
//! * Explanation of why a simulated instruction would be rejected.

use std::collections::HashMap;
use std::fmt;

// ── Register type system ───────────────────────────────────────────────────────

/// BPF register value type, mirroring the kernel's `bpf_reg_type`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum RegType {
    /// Register has not been initialised — any read is illegal.
    NotInit,
    /// An unknown / unconstrained integer scalar.
    ScalarValue,
    /// Pointer to the BPF program context (`struct xdp_md *`, `struct __sk_buff *`, etc.).
    PtrToCtx,
    /// Pointer into a map value.
    PtrToMapValue { map_id: u32, offset: i64 },
    /// Pointer to map value returned from `bpf_map_lookup_elem` that may be NULL.
    PtrToMapValueOrNull { map_id: u32 },
    /// Pointer to a stack slot.
    PtrToStack { frame: u32, offset: i64 },
    /// Pointer to packet data start.
    PtrToPacket { offset: i64 },
    /// Pointer to packet data end (sentinel).
    PtrToPacketEnd,
    /// Pointer to packet metadata area.
    PtrToPacketMeta { offset: i64 },
    /// Pointer to socket.
    PtrToSocket,
    /// Pointer to socket metadata.
    PtrToSocketOrNull,
    /// Pointer to a BPF spin lock.
    PtrToSpinLock,
    /// Pointer to per-CPU data.
    PtrToPercpuBtfId { btf_id: u32 },
    /// Pointer to BTF-typed kernel object.
    PtrToBtfId { btf_id: u32, offset: i64 },
    /// A 64-bit return value from a helper (could be error code or pointer).
    ReturnValue,
}

impl RegType {
    /// True if the type is a pointer that can be dereferenced.
    #[must_use]
    pub const fn is_ptr(&self) -> bool {
        !matches!(self, Self::NotInit | Self::ScalarValue | Self::ReturnValue)
    }

    /// True if this pointer type permits arithmetic (+/- scalar).
    #[must_use]
    pub const fn allows_arithmetic(&self) -> bool {
        matches!(
            self,
            Self::PtrToMapValue { .. }
            | Self::PtrToStack { .. }
            | Self::PtrToPacket { .. }
            | Self::PtrToPacketMeta { .. }
            | Self::PtrToBtfId { .. }
        )
    }

    /// True if this is a "maybe NULL" pointer.
    #[must_use]
    pub const fn may_be_null(&self) -> bool {
        matches!(
            self,
            Self::PtrToMapValueOrNull { .. }
            | Self::PtrToSocketOrNull
        )
    }

    /// Short name for error messages.
    #[must_use]
    pub const fn short_name(&self) -> &'static str {
        match self {
            Self::NotInit                => "NOT_INIT",
            Self::ScalarValue            => "SCALAR_VALUE",
            Self::PtrToCtx               => "PTR_TO_CTX",
            Self::PtrToMapValue { .. }   => "PTR_TO_MAP_VALUE",
            Self::PtrToMapValueOrNull{..}=> "PTR_TO_MAP_VALUE_OR_NULL",
            Self::PtrToStack { .. }      => "PTR_TO_STACK",
            Self::PtrToPacket { .. }     => "PTR_TO_PACKET",
            Self::PtrToPacketEnd         => "PTR_TO_PACKET_END",
            Self::PtrToPacketMeta { .. } => "PTR_TO_PACKET_META",
            Self::PtrToSocket            => "PTR_TO_SOCKET",
            Self::PtrToSocketOrNull      => "PTR_TO_SOCKET_OR_NULL",
            Self::PtrToSpinLock          => "PTR_TO_SPIN_LOCK",
            Self::PtrToPercpuBtfId { .. }=> "PTR_TO_PERCPU_BTF_ID",
            Self::PtrToBtfId { .. }      => "PTR_TO_BTF_ID",
            Self::ReturnValue            => "RETURN_VALUE",
        }
    }
}

impl fmt::Display for RegType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.short_name())
    }
}

// ── Scalar bounds tracking ─────────────────────────────────────────────────────

/// Known integer bounds for a scalar register (u64 and s64 ranges).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScalarBounds {
    pub umin: u64,
    pub umax: u64,
    pub smin: i64,
    pub smax: i64,
    pub tnum_value: u64,  // known bits (value portion of tnum)
    pub tnum_mask:  u64,  // unknown bits mask (1 = unknown)
}

impl ScalarBounds {
    /// Fully unknown scalar (any 64-bit value possible).
    #[must_use]
    pub const fn unknown() -> Self {
        Self {
            umin: 0, umax: u64::MAX,
            smin: i64::MIN, smax: i64::MAX,
            tnum_value: 0, tnum_mask: u64::MAX,
        }
    }

    /// Exact known constant.
    #[must_use]
    pub const fn exact(v: u64) -> Self {
        Self {
            umin: v, umax: v,
            smin: v as i64, smax: v as i64,
            tnum_value: v, tnum_mask: 0,
        }
    }

    /// True if the value is known to be zero.
    #[must_use]
    pub const fn is_known_zero(&self) -> bool {
        self.tnum_mask == 0 && self.tnum_value == 0
    }

    /// True if the value is a known constant.
    #[must_use]
    pub const fn is_const(&self) -> bool {
        self.tnum_mask == 0
    }

    /// True if the value is known to be in [0, `max_u32`].
    #[must_use]
    pub const fn is_u32_range(&self) -> bool {
        self.umax <= 0xFFFF_FFFF
    }
}

// ── Verifier register state ────────────────────────────────────────────────────

/// State of a single BPF register.
#[derive(Debug, Clone)]
pub struct RegState {
    pub reg_type: RegType,
    pub bounds: Option<ScalarBounds>,
    /// True if this register has been read at least once (liveness).
    pub live_read: bool,
    /// True if this register has been written.
    pub live_write: bool,
    /// If this register holds a spilled pointer, the frame + stack offset.
    pub spilled_ptr: Option<(u32, i64)>,
}

impl Default for RegState {
    fn default() -> Self {
        Self {
            reg_type: RegType::NotInit,
            bounds: None,
            live_read: false,
            live_write: false,
            spilled_ptr: None,
        }
    }
}

impl RegState {
    #[must_use]
    pub fn scalar(bounds: ScalarBounds) -> Self {
        Self {
            reg_type: RegType::ScalarValue,
            bounds: Some(bounds),
            ..Default::default()
        }
    }

    #[must_use]
    pub fn ctx() -> Self {
        Self {
            reg_type: RegType::PtrToCtx,
            bounds: None,
            ..Default::default()
        }
    }

    #[must_use]
    pub fn map_value(map_id: u32, offset: i64) -> Self {
        Self {
            reg_type: RegType::PtrToMapValue { map_id, offset },
            bounds: None,
            ..Default::default()
        }
    }
}

// ── Stack slot ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StackSlotKind {
    Misc,
    SpilledReg(Box<RegType>),
    Zero,
}

#[derive(Debug, Clone)]
pub struct StackSlot {
    pub kind: StackSlotKind,
    pub written: bool,
}

// ── Verifier error ────────────────────────────────────────────────────────────

/// An error produced by the simulated verifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifierError {
    /// Read from uninitialised register.
    UninitRegRead { reg: u8 },
    /// Pointer arithmetic on a type that does not allow it.
    InvalidPtrArith { reg: u8, reg_type: String },
    /// Dereference of a potentially-NULL pointer.
    NullPtrDeref { reg: u8 },
    /// Access to a packet pointer beyond the bounds of the data range.
    PacketOob { reg: u8, offset: i64 },
    /// Store of a pointer to the stack in an unaligned slot.
    UnalignedPtrSpill { offset: i64 },
    /// Load from a stack slot that was never written.
    UninitStackRead { offset: i64 },
    /// Context access at an offset not allowed for this program type.
    BadCtxAccess { offset: i64, size: u8 },
    /// Map value access out of the map's `value_size`.
    MapValueOob { map_id: u32, offset: i64, access_size: u8 },
    /// Helper argument type mismatch.
    HelperArgTypeMismatch { helper_id: u32, arg: u8, expected: String, got: String },
    /// Unreachable instruction (dead code after unconditional jump).
    UnreachableInsn { pc: usize },
    /// Program too large.
    TooManyInsns { count: usize, limit: usize },
    /// Recursion detected in the call graph.
    RecursiveCall { from: usize, to: usize },
    /// Generic rejection reason.
    Rejected(String),
}

impl fmt::Display for VerifierError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UninitRegRead { reg } =>
                write!(f, "R{reg} !read_ok"),
            Self::InvalidPtrArith { reg, reg_type } =>
                write!(f, "R{reg} pointer arithmetic on {reg_type} pointer"),
            Self::NullPtrDeref { reg } =>
                write!(f, "R{reg} is a potentially-NULL pointer, dereference must be guarded"),
            Self::PacketOob { reg, offset } =>
                write!(f, "R{reg} packet access at offset {offset} may be out of bounds"),
            Self::UnalignedPtrSpill { offset } =>
                write!(f, "unaligned spill of pointer to stack at offset {offset}"),
            Self::UninitStackRead { offset } =>
                write!(f, "invalid read from stack off={offset}"),
            Self::BadCtxAccess { offset, size } =>
                write!(f, "invalid access to context at off={offset} size={size}"),
            Self::MapValueOob { map_id, offset, access_size } =>
                write!(f, "map[{map_id}] value access at offset {offset}+{access_size} out of bounds"),
            Self::HelperArgTypeMismatch { helper_id, arg, expected, got } =>
                write!(f, "helper #{helper_id} arg{arg}: expected {expected}, got {got}"),
            Self::UnreachableInsn { pc } =>
                write!(f, "unreachable instruction at pc={pc}"),
            Self::TooManyInsns { count, limit } =>
                write!(f, "program has {count} instructions, limit is {limit}"),
            Self::RecursiveCall { from, to } =>
                write!(f, "recursive call from pc={from} to pc={to}"),
            Self::Rejected(s) =>
                write!(f, "rejected: {s}"),
        }
    }
}

// ── Map descriptor ────────────────────────────────────────────────────────────

/// Information about a BPF map referenced by the program.
#[derive(Debug, Clone)]
pub struct MapInfo {
    pub map_id: u32,
    pub key_size: u32,
    pub value_size: u32,
    pub max_entries: u32,
    pub map_type: u32, // BPF_MAP_TYPE_*
}

// ── Helper argument types ─────────────────────────────────────────────────────

/// Expected type for a helper function argument (simplified).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArgType {
    /// Any scalar value.
    Anything,
    /// Pointer to map.
    ConstMapPtr,
    /// Pointer to memory (read-only).
    PtrToMem,
    /// Pointer to memory (writable) with size in next arg.
    PtrToUninitMem,
    /// The size of the preceding `PtrToMem` argument.
    ConstSizeOrZero,
    /// Pointer to the program context.
    PtrToCtx,
    /// Pointer to socket.
    PtrToSock,
    /// Pointer to spin lock.
    PtrToSpinLock,
}

impl fmt::Display for ArgType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Anything           => "anything",
            Self::ConstMapPtr        => "const_map_ptr",
            Self::PtrToMem           => "ptr_to_mem",
            Self::PtrToUninitMem     => "ptr_to_uninit_mem",
            Self::ConstSizeOrZero    => "const_size_or_zero",
            Self::PtrToCtx           => "ptr_to_ctx",
            Self::PtrToSock          => "ptr_to_sock",
            Self::PtrToSpinLock      => "ptr_to_spin_lock",
        })
    }
}

/// Simplified helper function descriptor.
#[derive(Debug, Clone)]
pub struct HelperDesc {
    pub id: u32,
    pub name: &'static str,
    pub args: &'static [ArgType],
    pub ret_type: RegType,
}

/// Small table of common helpers used for type-checking.
pub static HELPER_TABLE: &[HelperDesc] = &[
    HelperDesc {
        id: 1,
        name: "bpf_map_lookup_elem",
        args: &[ArgType::ConstMapPtr, ArgType::PtrToMem],
        ret_type: RegType::PtrToMapValueOrNull { map_id: 0 },
    },
    HelperDesc {
        id: 2,
        name: "bpf_map_update_elem",
        args: &[ArgType::ConstMapPtr, ArgType::PtrToMem, ArgType::PtrToMem, ArgType::Anything],
        ret_type: RegType::ScalarValue,
    },
    HelperDesc {
        id: 3,
        name: "bpf_map_delete_elem",
        args: &[ArgType::ConstMapPtr, ArgType::PtrToMem],
        ret_type: RegType::ScalarValue,
    },
    HelperDesc {
        id: 4,
        name: "bpf_probe_read",
        args: &[ArgType::PtrToUninitMem, ArgType::ConstSizeOrZero, ArgType::Anything],
        ret_type: RegType::ScalarValue,
    },
    HelperDesc {
        id: 5,
        name: "bpf_ktime_get_ns",
        args: &[],
        ret_type: RegType::ScalarValue,
    },
    HelperDesc {
        id: 14,
        name: "bpf_get_current_pid_tgid",
        args: &[],
        ret_type: RegType::ScalarValue,
    },
    HelperDesc {
        id: 25,
        name: "bpf_perf_event_output",
        args: &[ArgType::PtrToCtx, ArgType::ConstMapPtr, ArgType::Anything,
                ArgType::PtrToMem, ArgType::ConstSizeOrZero],
        ret_type: RegType::ScalarValue,
    },
    HelperDesc {
        id: 66,
        name: "bpf_spin_lock",
        args: &[ArgType::PtrToSpinLock],
        ret_type: RegType::ScalarValue,
    },
    HelperDesc {
        id: 67,
        name: "bpf_spin_unlock",
        args: &[ArgType::PtrToSpinLock],
        ret_type: RegType::ScalarValue,
    },
];

// ── Verifier state ─────────────────────────────────────────────────────────────

/// Simulated verifier state at a program point.
#[derive(Debug, Clone)]
pub struct VerifierState {
    /// Register states R0–R10 (index = register number).
    pub regs: [RegState; 11],
    /// Stack: maps offset (negative, from 0) to slot.
    pub stack: HashMap<i64, StackSlot>,
    /// Current call frame depth.
    pub frame_depth: u32,
    /// Maps referenced by the program (`map_id` → `MapInfo`).
    pub maps: HashMap<u32, MapInfo>,
    /// Program type (XDP=6, `SOCKET_FILTER=1`, etc.).
    pub prog_type: u32,
    /// Errors/warnings accumulated so far.
    pub errors: Vec<VerifierError>,
}

impl VerifierState {
    /// Create an initial verifier state for the program entry point.
    ///
    /// Per the ABI, R1 holds a pointer to the program context, R0 and R2–R10
    /// are uninitialised (R10 = read-only frame pointer).
    #[must_use]
    pub fn initial(prog_type: u32, maps: HashMap<u32, MapInfo>) -> Self {
        let mut regs: [RegState; 11] = Default::default();
        regs[1] = RegState::ctx();
        // R10 is the read-only frame pointer.
        regs[10] = RegState {
            reg_type: RegType::PtrToStack { frame: 0, offset: 0 },
            bounds: None,
            live_read: false,
            live_write: true,
            spilled_ptr: None,
        };
        Self {
            regs,
            stack: HashMap::new(),
            frame_depth: 0,
            maps,
            prog_type,
            errors: Vec::new(),
        }
    }

    /// Check that a register is readable (not `NOT_INIT`).
    pub fn check_reg_read(&mut self, reg: u8) -> Result<(), VerifierError> {
        if self.regs[reg as usize].reg_type == RegType::NotInit {
            let e = VerifierError::UninitRegRead { reg };
            self.errors.push(e.clone());
            return Err(e);
        }
        self.regs[reg as usize].live_read = true;
        Ok(())
    }

    /// Check that a pointer register is not potentially NULL before dereference.
    pub fn check_not_null(&mut self, reg: u8) -> Result<(), VerifierError> {
        if self.regs[reg as usize].reg_type.may_be_null() {
            let e = VerifierError::NullPtrDeref { reg };
            self.errors.push(e.clone());
            return Err(e);
        }
        Ok(())
    }

    /// Simulate ALU operation: `dst_reg` = `dst_reg` OP `src_reg`.
    ///
    /// Only models pointer+scalar arithmetic and scalar+scalar.
    pub fn sim_alu64_reg(&mut self, opcode: u8, dst: u8, src: u8) -> Result<(), VerifierError> {
        self.check_reg_read(src)?;
        self.check_reg_read(dst)?;
        let dst_type = self.regs[dst as usize].reg_type.clone();
        let src_type = self.regs[src as usize].reg_type.clone();

        // ADD is the only op that can mix pointer + scalar.
        if opcode == 0x0 /* ADD */ || opcode == 0x1 /* SUB */ {
            match (&dst_type, &src_type) {
                (_, RegType::ScalarValue) if dst_type.is_ptr() => {
                    if !dst_type.allows_arithmetic() {
                        let e = VerifierError::InvalidPtrArith {
                            reg: dst,
                            reg_type: dst_type.short_name().to_string(),
                        };
                        self.errors.push(e.clone());
                        return Err(e);
                    }
                    // Update offset.
                    match &mut self.regs[dst as usize].reg_type {
                        RegType::PtrToMapValue { offset, .. }
                        | RegType::PtrToStack { offset, .. }
                        | RegType::PtrToPacket { offset }
                        | RegType::PtrToBtfId { offset, .. } => {
                            // We don't know the exact delta; mark as uncertain.
                            *offset = i64::MIN; // sentinel = "offset unknown after arith"
                        }
                        _ => {}
                    }
                    return Ok(());
                }
                (RegType::ScalarValue, RegType::ScalarValue) => {
                    // Scalar math, bounds become imprecise.
                    self.regs[dst as usize].bounds = Some(ScalarBounds::unknown());
                    return Ok(());
                }
                _ => {}
            }
        }

        // For all other ops, result is a scalar (conservatively).
        self.regs[dst as usize] = RegState::scalar(ScalarBounds::unknown());
        self.regs[dst as usize].live_write = true;
        Ok(())
    }

    /// Simulate a load from memory: dst = *(src + offset).
    pub fn sim_ldx(&mut self, dst: u8, src: u8, offset: i16, size: u8) -> Result<(), VerifierError> {
        self.check_reg_read(src)?;
        self.check_not_null(src)?;
        let src_type = self.regs[src as usize].reg_type.clone();

        match &src_type {
            RegType::PtrToStack { frame, offset: base_off } => {
                let stack_key = base_off.wrapping_add(i64::from(offset));
                if let Some(slot) = self.stack.get(&stack_key) {
                    if !slot.written {
                        let e = VerifierError::UninitStackRead { offset: stack_key };
                        self.errors.push(e.clone());
                        return Err(e);
                    }
                    if let StackSlotKind::SpilledReg(ref t) = slot.kind {
                        self.regs[dst as usize] = RegState {
                            reg_type: *t.clone(),
                            bounds: None,
                            live_write: true,
                            ..Default::default()
                        };
                        return Ok(());
                    }
                    let _ = frame;
                } else {
                    let e = VerifierError::UninitStackRead { offset: stack_key };
                    self.errors.push(e.clone());
                    return Err(e);
                }
            }
            RegType::PtrToMapValue { map_id, offset: base_off } => {
                let total = base_off.wrapping_add(i64::from(offset));
                if let Some(map) = self.maps.get(map_id)
                    && (total < 0 || (total as u64) + u64::from(size) > u64::from(map.value_size)) {
                        let e = VerifierError::MapValueOob {
                            map_id: *map_id,
                            offset: total,
                            access_size: size,
                        };
                        self.errors.push(e.clone());
                        return Err(e);
                    }
            }
            RegType::PtrToPacket { offset: base_off } => {
                let total = base_off.wrapping_add(i64::from(offset));
                if total < 0 {
                    let e = VerifierError::PacketOob { reg: src, offset: total };
                    self.errors.push(e.clone());
                    return Err(e);
                }
                // Without a data_end comparison, we can't guarantee packet safety.
                // A real verifier would require a bounds check before this access.
            }
            RegType::PtrToCtx
                // Context access: depends on prog_type.  Simplified: any offset ≤ 256 OK.
                if (i64::from(offset) < 0 || i64::from(offset) > 256) => {
                    let e = VerifierError::BadCtxAccess { offset: i64::from(offset), size };
                    self.errors.push(e.clone());
                    return Err(e);
                }
            _ => {}
        }

        // Loaded value is a scalar (we don't track what map values contain here).
        self.regs[dst as usize] = RegState::scalar(ScalarBounds::unknown());
        self.regs[dst as usize].live_write = true;
        Ok(())
    }

    /// Simulate a store to memory: *(dst + offset) = src.
    pub fn sim_stx(&mut self, dst: u8, src: u8, offset: i16, _size: u8) -> Result<(), VerifierError> {
        self.check_reg_read(dst)?;
        self.check_reg_read(src)?;
        self.check_not_null(dst)?;
        let dst_type = self.regs[dst as usize].reg_type.clone();

        if let RegType::PtrToStack { offset: base_off, .. } = dst_type {
            let stack_key = base_off.wrapping_add(i64::from(offset));
            // Storing a pointer requires aligned slot.
            let src_type = self.regs[src as usize].reg_type.clone();
            if src_type.is_ptr() && stack_key % 8 != 0 {
                let e = VerifierError::UnalignedPtrSpill { offset: stack_key };
                self.errors.push(e.clone());
                return Err(e);
            }
            let kind = if src_type.is_ptr() {
                StackSlotKind::SpilledReg(Box::new(src_type))
            } else {
                StackSlotKind::Misc
            };
            self.stack.insert(stack_key, StackSlot { kind, written: true });
        }
        Ok(())
    }

    /// Simulate a `BPF_CALL` to a helper by ID.
    pub fn sim_helper_call(&mut self, helper_id: u32) -> Result<(), VerifierError> {
        // R1–R5 are clobbered by the call.
        for r in 1..=5u8 {
            self.check_reg_read(r).ok(); // don't fail, just mark
        }

        let Some(desc) = HELPER_TABLE.iter().find(|h| h.id == helper_id) else {
            // Unknown helper — conservatively mark R0 as scalar.
            self.regs[0] = RegState::scalar(ScalarBounds::unknown());
            self.regs[0].live_write = true;
            return Ok(());
        };

        // Validate argument types.
        for (i, expected) in desc.args.iter().enumerate() {
            let reg = (i + 1) as u8;
            if reg > 5 { break; }
            let actual = &self.regs[reg as usize].reg_type;
            let ok = match expected {
                ArgType::Anything => true,
                // ConstMapPtr is checked as a context pointer (simplified),
                // which is exactly the PtrToCtx check.
                ArgType::ConstMapPtr | ArgType::PtrToCtx => matches!(actual, RegType::PtrToCtx),
                ArgType::PtrToMem | ArgType::PtrToUninitMem =>
                    actual.is_ptr() && !actual.may_be_null(),
                ArgType::ConstSizeOrZero => matches!(actual, RegType::ScalarValue),
                ArgType::PtrToSock => matches!(actual, RegType::PtrToSocket),
                ArgType::PtrToSpinLock => matches!(actual, RegType::PtrToSpinLock),
            };
            if !ok {
                let e = VerifierError::HelperArgTypeMismatch {
                    helper_id,
                    arg: reg,
                    expected: expected.to_string(),
                    got: actual.short_name().to_string(),
                };
                self.errors.push(e.clone());
                return Err(e);
            }
        }

        // After call: R1–R5 are unknown, R0 = return value.
        for r in 1..=5u8 {
            self.regs[r as usize] = RegState::default(); // NOT_INIT
        }
        let mut ret = RegState {
            reg_type: desc.ret_type.clone(),
            bounds: Some(ScalarBounds::unknown()),
            live_write: true,
            ..Default::default()
        };
        if matches!(desc.ret_type, RegType::ScalarValue) {
            ret.bounds = Some(ScalarBounds::unknown());
        }
        self.regs[0] = ret;
        Ok(())
    }

    /// Simulate `BPF_EXIT`.  R0 must be initialised.
    pub fn sim_exit(&mut self) -> Result<(), VerifierError> {
        self.check_reg_read(0)?;
        Ok(())
    }

    /// Generate a human-readable report of the current register state.
    #[must_use]
    pub fn state_report(&self) -> String {
        let mut out = String::new();
        for (i, reg) in self.regs.iter().enumerate() {
            let bounds_str = match &reg.bounds {
                Some(b) if b.is_const() => format!(" = 0x{:X}", b.tnum_value),
                Some(b) => format!(" umin={} umax={}", b.umin, b.umax),
                None => String::new(),
            };
            out.push_str(&format!("  R{i:2}: {}{}\n", reg.reg_type, bounds_str));
        }
        if !self.stack.is_empty() {
            out.push_str("  Stack:\n");
            let mut slots: Vec<_> = self.stack.iter().collect();
            slots.sort_by_key(|&(&k, _)| k);
            for (off, slot) in slots {
                let desc = match &slot.kind {
                    StackSlotKind::SpilledReg(t) => format!("spilled {t:?}"),
                    StackSlotKind::Misc => "misc".to_string(),
                    StackSlotKind::Zero => "zero".to_string(),
                };
                out.push_str(&format!("    fp{off:+4}: {desc}\n"));
            }
        }
        if !self.errors.is_empty() {
            out.push_str("  Errors:\n");
            for e in &self.errors {
                out.push_str(&format!("    ! {e}\n"));
            }
        }
        out
    }
}



// ── Verifier trace entry ───────────────────────────────────────────────────────

/// One step in the verifier simulation trace.
#[derive(Debug, Clone)]
pub struct VerifierTrace {
    pub pc: usize,
    pub insn_text: String,
    pub result: Result<(), VerifierError>,
    pub r0_after: String,
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_state() -> VerifierState {
        VerifierState::initial(1, HashMap::new())
    }

    #[test]
    fn initial_r1_is_ctx() {
        let st = empty_state();
        assert_eq!(st.regs[1].reg_type, RegType::PtrToCtx);
    }

    #[test]
    fn uninit_read_error() {
        let mut st = empty_state();
        let err = st.check_reg_read(2).unwrap_err();
        assert!(matches!(err, VerifierError::UninitRegRead { reg: 2 }));
    }

    #[test]
    fn null_ptr_deref_error() {
        let mut st = empty_state();
        st.regs[2].reg_type = RegType::PtrToMapValueOrNull { map_id: 1 };
        let err = st.check_not_null(2).unwrap_err();
        assert!(matches!(err, VerifierError::NullPtrDeref { reg: 2 }));
    }

    #[test]
    fn scalar_alu_no_error() {
        let mut st = empty_state();
        st.regs[2] = RegState::scalar(ScalarBounds::exact(42));
        st.regs[3] = RegState::scalar(ScalarBounds::exact(1));
        assert!(st.sim_alu64_reg(0x0, 2, 3).is_ok());
    }

    #[test]
    fn ptr_to_ctx_arithmetic_rejected() {
        let mut st = empty_state();
        st.regs[2] = RegState::scalar(ScalarBounds::exact(4));
        // R1 = PTR_TO_CTX — arithmetic not allowed.
        let err = st.sim_alu64_reg(0x0, 1, 2).unwrap_err();
        assert!(matches!(err, VerifierError::InvalidPtrArith { .. }));
    }

    #[test]
    fn stack_uninit_read() {
        let mut st = empty_state();
        st.regs[1] = RegState {
            reg_type: RegType::PtrToStack { frame: 0, offset: 0 },
            ..Default::default()
        };
        let err = st.sim_ldx(0, 1, -8, 8).unwrap_err();
        assert!(matches!(err, VerifierError::UninitStackRead { .. }));
    }

    #[test]
    fn helper_call_sets_r0() {
        let mut st = empty_state();
        // bpf_ktime_get_ns (id=5) takes no args.
        assert!(st.sim_helper_call(5).is_ok());
        assert_eq!(st.regs[0].reg_type, RegType::ScalarValue);
    }

    #[test]
    fn exit_requires_r0_init() {
        let mut st = empty_state();
        let err = st.sim_exit().unwrap_err();
        assert!(matches!(err, VerifierError::UninitRegRead { reg: 0 }));
    }

    #[test]
    fn state_report_no_panic() {
        let st = empty_state();
        let rep = st.state_report();
        assert!(rep.contains("PTR_TO_CTX"));
    }
}
