//! Concrete LLIL interpreter for `rustre-il-llil`.
//!
//! Executes LLIL instructions step-by-step against a mutable [`CpuState`] and
//! a byte-addressable [`MemoryState`].  A pluggable [`SyscallInterceptor`] lets
//! callers handle system calls without embedding OS logic here.  Execution
//! statistics are tracked in [`InterpreterStats`].

use std::collections::HashMap;
use std::fmt;

// AHashMap uses a DOS-resistant non-cryptographic hash (aHash), which defeats
// hash-flooding attacks that are possible with std::HashMap's default SipHash
// when keys are attacker-controlled (e.g. virtual addresses from a binary).
use ahash::AHashMap;

use crate::{LlilExpr, LlilFunction, LlilInstruction, LlilRegister, Size};
use rustre_core::address::Address;

/// Type alias for the core address type, exposed so interpreter callers can
/// refer to instruction-pointer values without an extra `rustre_core` dependency.
pub type InterpreterAddress = Address;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors produced during interpretation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InterpError {
    /// The interpreter reached an instruction it cannot handle.
    UnsupportedInstruction(String),
    /// Memory access out of mapped range.
    UnmappedMemory(u64),
    /// Integer division by zero.
    DivisionByZero,
    /// Undefined expression was evaluated.
    UndefinedValue,
    /// A system call was requested and no interceptor is installed.
    UnhandledSyscall(u64),
    /// Execution limit exceeded.
    StepLimitExceeded,
    /// An intrinsic could not be evaluated.
    UnknownIntrinsic(String),
    /// Stack underflow (e.g. pop from empty stack).
    StackUnderflow,
    /// Two instructions share the same address in a loaded function.
    DuplicateAddress(u64),
}

impl fmt::Display for InterpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedInstruction(s) => write!(f, "unsupported instruction: {s}"),
            Self::UnmappedMemory(a) => write!(f, "unmapped memory at {a:#x}"),
            Self::DivisionByZero => write!(f, "division by zero"),
            Self::UndefinedValue => write!(f, "undefined value"),
            Self::UnhandledSyscall(n) => write!(f, "unhandled syscall #{n}"),
            Self::StepLimitExceeded => write!(f, "step limit exceeded"),
            Self::UnknownIntrinsic(s) => write!(f, "unknown intrinsic: {s}"),
            Self::StackUnderflow => write!(f, "stack underflow"),
            Self::DuplicateAddress(a) => write!(f, "duplicate instruction address {a:#x}"),
        }
    }
}

impl std::error::Error for InterpError {}

/// Converge interpreter failures onto the workspace-wide cross-tier error type
/// owned by `rustre-il`, tagged at [`rustre_il::IlTier::Llil`].
///
/// Only [`InterpError::UnsupportedInstruction`] names an operation the tier
/// cannot express, so it is the one that maps to
/// [`rustre_il::IlError::Unsupported`]; the rest are runtime faults and keep
/// their `Display` text inside [`rustre_il::IlError::Invalid`].
impl From<InterpError> for rustre_il::IlError {
    fn from(e: InterpError) -> Self {
        match e {
            InterpError::UnsupportedInstruction(s) => Self::Unsupported {
                tier: rustre_il::IlTier::Llil,
                op: s,
            },
            other => Self::Invalid(other.to_string()),
        }
    }
}

// ---------------------------------------------------------------------------
// FlagUpdate
// ---------------------------------------------------------------------------

/// A single flag update produced by an instruction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlagUpdate {
    /// Name of the architectural flag.
    pub name: String,
    /// New value (0 = clear, 1 = set).
    pub value: u64,
}

impl FlagUpdate {
    /// Construct a [`FlagUpdate`] that sets the named flag.
    #[must_use]
    pub fn set(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value: 1,
        }
    }

    /// Construct a [`FlagUpdate`] that clears the named flag.
    #[must_use]
    pub fn clear(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// MemoryState
// ---------------------------------------------------------------------------

/// Byte-addressable, sparse memory model.
///
/// Memory is stored in page-sized chunks.  An unmapped address returns an
/// error rather than silently returning zero so analysis bugs surface early.
///
/// `pages` uses `AHashMap` (DOS-resistant hash) because the keys are virtual
/// addresses derived from attacker-supplied binary content; `HashMap` with its
/// default `SipHash` is still vulnerable to hash-flooding in Rust < 1.36 and
/// on targets where `SipHash` is intentionally weakened.  `AHashMap` is always
/// randomised per-process and uses a significantly faster primitive.
#[derive(Debug, Clone)]
pub struct MemoryState {
    /// Underlying storage: page-aligned addr → page bytes.
    pages: AHashMap<u64, Vec<u8>>,
    /// Page size (always a power of two; stored as `usize` for direct indexing).
    page_size: usize,
    /// Whether unmapped reads should return zero instead of erroring.
    lenient: bool,
}

impl MemoryState {
    const DEFAULT_PAGE_SIZE: usize = 4096;

    /// Create a new empty memory state.
    #[must_use]
    pub fn new() -> Self {
        Self {
            pages: AHashMap::new(),
            page_size: Self::DEFAULT_PAGE_SIZE,
            lenient: false,
        }
    }

    /// Create a lenient memory state (unmapped reads return 0).
    #[must_use]
    pub fn lenient() -> Self {
        Self {
            lenient: true,
            ..Self::new()
        }
    }

    /// Map a byte range starting at `base` with the given `data`.
    ///
    /// Bytes that would wrap past `u64::MAX` are silently dropped rather than
    /// being mapped at low addresses (e.g. address 0), which could let an
    /// attacker overwrite previously-mapped regions by crafting an oversized
    /// section header.
    pub fn map(&mut self, base: u64, data: &[u8]) {
        let ps = u64::try_from(self.page_size).unwrap_or(u64::MAX);
        let ps_mask = ps - 1;
        for (i, &byte) in data.iter().enumerate() {
            // Detect address-space wrap: if base + i overflows u64, stop.
            let Some(addr) = base.checked_add(u64::try_from(i).unwrap_or(u64::MAX)) else {
                break; // truncate rather than wrap to address 0
            };
            let page = addr & !ps_mask;
            let off = usize::try_from(addr & ps_mask).unwrap_or(0);
            let pg = self
                .pages
                .entry(page)
                .or_insert_with(|| vec![0u8; self.page_size]);
            pg[off] = byte;
        }
    }

    /// Read `size` bytes from `addr`, little-endian, as a `u64`.
    ///
    /// # Errors
    /// Returns [`InterpError::UnmappedMemory`] if any byte in the range is not mapped
    /// (unless the memory state is lenient, in which case unmapped bytes read as zero).
    /// Bytes past `u64::MAX` are treated as unmapped (consistent with [`Self::map`],
    /// which never wraps the address space).
    pub fn read(&self, addr: u64, size: Size) -> Result<u64, InterpError> {
        let n = size.bytes();
        let mut val = 0u64;
        for i in 0..n {
            let Some(byte_addr) = addr.checked_add(i as u64) else {
                // Address space wrapped: map() never places bytes there, so this
                // region is by definition unmapped.
                if self.lenient {
                    continue; // reads as zero
                }
                return Err(InterpError::UnmappedMemory(u64::MAX));
            };
            val |= u64::from(self.read_byte(byte_addr)?) << (i * 8);
        }
        Ok(val)
    }

    /// Write `value` of `size` bytes to `addr`, little-endian.
    ///
    /// Bytes that would wrap past `u64::MAX` are silently dropped, consistent
    /// with [`Self::map`] (never wrap to address 0).
    pub fn write(&mut self, addr: u64, value: u64, size: Size) {
        let n = size.bytes();
        for i in 0..n {
            let Some(byte_addr) = addr.checked_add(i as u64) else {
                break; // truncate rather than wrap to address 0
            };
            let byte = ((value >> (i * 8)) & 0xff) as u8;
            self.write_byte(byte_addr, byte);
        }
    }

    fn read_byte(&self, addr: u64) -> Result<u8, InterpError> {
        let ps = u64::try_from(self.page_size).unwrap_or(u64::MAX);
        let page = addr & !(ps - 1);
        let off = usize::try_from(addr & (ps - 1)).unwrap_or(0);
        match self.pages.get(&page) {
            Some(pg) => Ok(pg[off]),
            None if self.lenient => Ok(0),
            None => Err(InterpError::UnmappedMemory(addr)),
        }
    }

    fn write_byte(&mut self, addr: u64, byte: u8) {
        let ps = u64::try_from(self.page_size).unwrap_or(u64::MAX);
        let page = addr & !(ps - 1);
        let off = usize::try_from(addr & (ps - 1)).unwrap_or(0);
        let pg = self
            .pages
            .entry(page)
            .or_insert_with(|| vec![0u8; self.page_size]);
        pg[off] = byte;
    }

    /// Total number of mapped bytes.
    #[must_use]
    pub fn mapped_bytes(&self) -> usize {
        self.pages.len() * self.page_size
    }
}

impl Default for MemoryState {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// CpuState
// ---------------------------------------------------------------------------

/// Concrete CPU register + flag state.
#[derive(Debug, Clone)]
pub struct CpuState {
    /// Register file: name → value (u64, width managed by callers).
    registers: HashMap<String, u64>,
    /// Architectural flags: name → value (0 or 1).
    flags: HashMap<String, u64>,
    /// Program counter (current instruction address).
    pub pc: u64,
    /// Stack pointer value.
    pub sp: u64,
    /// Pointer width in bytes (4 or 8).
    pub ptr_size: usize,
}

impl CpuState {
    /// Create a [`CpuState`] with an empty register file.
    #[must_use]
    pub fn new(ptr_size: usize) -> Self {
        Self {
            registers: HashMap::new(),
            flags: HashMap::new(),
            pc: 0,
            sp: 0,
            ptr_size,
        }
    }

    /// Read a register value (returns 0 for unknown registers).
    #[must_use]
    pub fn read_reg(&self, name: &str) -> u64 {
        *self.registers.get(name).unwrap_or(&0)
    }

    /// Write a register value.
    pub fn write_reg(&mut self, name: &str, value: u64) {
        self.registers.insert(name.to_owned(), value);
    }

    /// x86 sub-register alias table: `name -> (64-bit parent name, byte
    /// offset within the parent, width in bytes)`. Covers the legacy
    /// al/ah/ax/eax/rax-style family for rax/rbx/rcx/rdx/rsi/rdi/rbp/rsp and
    /// the uniform bN/wN/dN/(no suffix) family for r8-r15. `None` for any
    /// name outside this table (other architectures, temporaries, `rip`,
    /// non-GPR names) — those fall back to plain by-name storage exactly
    /// like [`Self::read_reg`]/[`Self::write_reg`].
    fn x86_alias(name: &str) -> Option<(&'static str, u32, u32)> {
        const LEGACY: &[(&str, &str, &str, &str)] = &[
            ("al", "ah", "ax", "eax"),
            ("bl", "bh", "bx", "ebx"),
            ("cl", "ch", "cx", "ecx"),
            ("dl", "dh", "dx", "edx"),
        ];
        for &(lo, hi, word, dword) in LEGACY {
            let parent = match lo {
                "al" => "rax",
                "bl" => "rbx",
                "cl" => "rcx",
                "dl" => "rdx",
                _ => unreachable!(),
            };
            if name == lo {
                return Some((parent, 0, 1));
            }
            if name == hi {
                return Some((parent, 1, 1));
            }
            if name == word {
                return Some((parent, 0, 2));
            }
            if name == dword {
                return Some((parent, 0, 4));
            }
            if name == parent {
                return Some((parent, 0, 8));
            }
        }
        // No legacy high-byte form for these (sil/dil/bpl/spl ARE valid
        // 8-bit names in 64-bit mode, but have no `xh`-style high alias).
        const NO_HIGH_BYTE: &[(&str, &str, &str, &str)] = &[
            ("sil", "si", "esi", "rsi"),
            ("dil", "di", "edi", "rdi"),
            ("bpl", "bp", "ebp", "rbp"),
            ("spl", "sp", "esp", "rsp"),
        ];
        for &(b, w, d, parent) in NO_HIGH_BYTE {
            if name == b {
                return Some((parent, 0, 1));
            }
            if name == w {
                return Some((parent, 0, 2));
            }
            if name == d {
                return Some((parent, 0, 4));
            }
            if name == parent {
                return Some((parent, 0, 8));
            }
        }
        for n in 8..=15u32 {
            let parent: &'static str = match n {
                8 => "r8",
                9 => "r9",
                10 => "r10",
                11 => "r11",
                12 => "r12",
                13 => "r13",
                14 => "r14",
                15 => "r15",
                _ => unreachable!(),
            };
            if name == parent {
                return Some((parent, 0, 8));
            }
            if name == format!("{parent}d") {
                return Some((parent, 0, 4));
            }
            if name == format!("{parent}w") {
                return Some((parent, 0, 2));
            }
            if name == format!("{parent}b") {
                return Some((parent, 0, 1));
            }
        }
        None
    }

    /// Alias-aware register read: `al`/`ah`/`ax`/`eax`/`rax` (and the rest
    /// of the x86 GPR family) all read through the SAME underlying 64-bit
    /// storage slot, extracting the requested byte range — unlike
    /// [`Self::read_reg`], which treats every name as an independent slot.
    /// Falls back to [`Self::read_reg`] for any name outside the x86 GPR
    /// alias table (see [`Self::x86_alias`]).
    #[must_use]
    pub fn read_reg_aliased(&self, name: &str) -> u64 {
        let Some((parent, byte_offset, width)) = Self::x86_alias(name) else {
            return self.read_reg(name);
        };
        let parent_val = self.read_reg(parent);
        let shift = byte_offset * 8;
        let mask: u64 = if width >= 8 { u64::MAX } else { (1u64 << (width * 8)) - 1 };
        (parent_val >> shift) & mask
    }

    /// Alias-aware register write: writes THROUGH the same underlying
    /// 64-bit storage slot the whole x86 GPR family shares, so a later
    /// [`Self::read_reg_aliased`] of a wider/narrower alias observes the
    /// write — unlike [`Self::write_reg`], which stores every name
    /// independently. Per the AMD APM, an 8/16-bit write leaves the rest of
    /// the parent register untouched (read-modify-write); a 32-bit write
    /// zero-extends the full 64-bit parent (x86-64 default operand-size
    /// promotion). Falls back to [`Self::write_reg`] for any name outside
    /// the x86 GPR alias table.
    pub fn write_reg_aliased(&mut self, name: &str, value: u64) {
        let Some((parent, byte_offset, width)) = Self::x86_alias(name) else {
            self.write_reg(name, value);
            return;
        };
        if width >= 8 {
            self.write_reg(parent, value);
            return;
        }
        if width == 4 {
            // 32-bit write zero-extends the full 64-bit register.
            self.write_reg(parent, value & 0xFFFF_FFFF);
            return;
        }
        // 8/16-bit write: read-modify-write, preserving the untouched bits.
        let shift = byte_offset * 8;
        let width_mask: u64 = (1u64 << (width * 8)) - 1;
        let old = self.read_reg(parent);
        let cleared = old & !(width_mask << shift);
        let new = cleared | ((value & width_mask) << shift);
        self.write_reg(parent, new);
    }

    /// Read a flag (returns 0 for unknown flags).
    #[must_use]
    pub fn read_flag(&self, name: &str) -> u64 {
        *self.flags.get(name).unwrap_or(&0)
    }

    /// Write a flag value (should be 0 or 1).
    pub fn write_flag(&mut self, name: &str, value: u64) {
        self.flags.insert(name.to_owned(), value);
    }

    /// Apply a batch of [`FlagUpdate`]s.
    pub fn apply_flags(&mut self, updates: &[FlagUpdate]) {
        for u in updates {
            self.write_flag(&u.name, u.value);
        }
    }

    /// Mask `value` to the bit-width implied by `size`.
    #[must_use]
    pub const fn mask(value: u64, size: Size) -> u64 {
        match size {
            Size::Byte => value & 0xff,
            Size::Word => value & 0xffff,
            Size::DWord => value & 0xffff_ffff,
            Size::QWord | Size::OWord | Size::YWord | Size::ZWord => value, // upper bits beyond 64 not tracked (OWord/YWord/ZWord: AVX/AVX-512 vector widths)
        }
    }

    /// Pointer-size [`Size`] variant.
    #[must_use]
    pub const fn ptr_size_variant(&self) -> Size {
        match self.ptr_size {
            4 => Size::DWord,
            _ => Size::QWord,
        }
    }
}

// ---------------------------------------------------------------------------
// SyscallInterceptor
// ---------------------------------------------------------------------------

/// Interceptor called when a [`LlilInstruction::SysCall`] is executed.
///
/// Implementors receive a mutable reference to the full interpreter so they
/// can inspect / mutate both CPU and memory state.  The interceptor should
/// return `Ok(())` if it handled the call or `Err(InterpError)` otherwise.
pub trait SyscallInterceptor: fmt::Debug {
    /// Handle a system call.  The syscall number is typically found in a
    /// convention-specific register (e.g. `rax` on Linux x86-64).
    /// # Errors
    /// Returns an [`InterpError`] if the system call fails or is not supported.
    fn handle(&mut self, interp: &mut LlilInterpreter) -> Result<(), InterpError>;
}

/// A no-op syscall interceptor that always returns [`InterpError::UnhandledSyscall`].
#[derive(Debug, Default)]
pub struct NullInterceptor;

impl SyscallInterceptor for NullInterceptor {
    fn handle(&mut self, interp: &mut LlilInterpreter) -> Result<(), InterpError> {
        let nr = interp.cpu.read_reg("rax");
        Err(InterpError::UnhandledSyscall(nr))
    }
}

// ---------------------------------------------------------------------------
// InterpreterStats
// ---------------------------------------------------------------------------

/// Execution statistics accumulated during interpretation.
#[derive(Debug, Clone, Default)]
pub struct InterpreterStats {
    /// Total instructions executed.
    pub instructions_executed: u64,
    /// Memory reads performed.
    pub memory_reads: u64,
    /// Memory writes performed.
    pub memory_writes: u64,
    /// Conditional branches taken (true-destination).
    pub branches_taken: u64,
    /// Conditional branches not taken (false-destination).
    pub branches_not_taken: u64,
    /// System calls intercepted.
    pub syscalls: u64,
    /// Number of times a flag was written.
    pub flag_writes: u64,
}

impl InterpreterStats {
    /// Total branch count.
    #[must_use]
    pub const fn total_branches(&self) -> u64 {
        self.branches_taken + self.branches_not_taken
    }

    /// Branch-taken rate in [0.0, 1.0].
    #[must_use]
    pub fn branch_taken_rate(&self) -> f64 {
        let total = self.total_branches();
        if total == 0 {
            0.0
        } else {
            f64::from(u32::try_from(self.branches_taken).unwrap_or(u32::MAX))
                / f64::from(u32::try_from(total).unwrap_or(u32::MAX))
        }
    }
}

// ---------------------------------------------------------------------------
// StepResult
// ---------------------------------------------------------------------------

/// Outcome of a single interpreter step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StepResult {
    /// Execution continues normally; PC has been updated.
    Continue,
    /// A `Ret` instruction was executed.
    Returned,
    /// A `Call` instruction was executed; target is the callee address.
    Called(u64),
    /// A conditional branch; `bool` is `true` if taken.
    Branch { taken: bool, target: u64 },
    /// A system call was handled.
    Syscall,
}

// ---------------------------------------------------------------------------
// LlilInterpreter
// ---------------------------------------------------------------------------

/// Maximum expression tree depth allowed before returning
/// [`InterpError::UnsupportedInstruction`].  Prevents stack overflow when
/// evaluating deeply-nested expressions produced from adversarial input.
const MAX_EXPR_DEPTH: u32 = 256;

/// Concrete, single-step LLIL interpreter.
///
/// # Example
///
/// ```
/// use rustre_il_llil::llil_interpreter::{CpuState, LlilInterpreter, MemoryState};
///
/// let mut interp = LlilInterpreter::new(CpuState::new(8), MemoryState::new());
/// interp.cpu.write_reg("rax", 42);
///
/// // With no function loaded there is nothing to step.
/// assert!(interp.step().is_err());
/// ```
///
/// Until 2026-07-29 this doc block sat ABOVE `MAX_EXPR_DEPTH`, so the
/// constant was documented as "Concrete, single-step LLIL interpreter"
/// while this type had no documentation at all — someone inserted the
/// constant between the comment and the item it describes. The example
/// was also `rust,ignore` and referred to an undefined `func`.
#[derive(Debug)]
pub struct LlilInterpreter {
    /// Current CPU register / flag state.
    pub cpu: CpuState,
    /// Byte-addressable memory.
    pub mem: MemoryState,
    /// Accumulated execution statistics.
    pub stats: InterpreterStats,
    /// Maximum step count before [`InterpError::StepLimitExceeded`].
    pub step_limit: u64,
    /// Current step count.
    steps: u64,
    /// Instruction stream indexed by address (`AHashMap`: DOS-resistant against
    /// attacker-controlled virtual addresses from the binary).
    instructions: AHashMap<u64, LlilInstruction>,
    /// Instruction ordering (addresses in linear order).
    order: Vec<u64>,
    /// Index into `order` for the current PC.
    pc_index: usize,
    /// Set when execution fell off the end of the loaded instructions.
    halted: bool,
    /// Optional syscall interceptor.
    syscall_interceptor: Box<dyn SyscallInterceptor>,
    /// Current expression recursion depth (reset each instruction).
    expr_depth: u32,
}

impl LlilInterpreter {
    /// Construct an interpreter with the given initial state.
    #[must_use]
    pub fn new(cpu: CpuState, mem: MemoryState) -> Self {
        Self {
            cpu,
            mem,
            stats: InterpreterStats::default(),
            step_limit: 1_000_000,
            expr_depth: 0,
            steps: 0,
            instructions: AHashMap::new(),
            order: Vec::new(),
            pc_index: 0,
            halted: false,
            syscall_interceptor: Box::new(NullInterceptor),
        }
    }

    /// Install a custom syscall interceptor.
    pub fn set_syscall_interceptor(&mut self, interceptor: Box<dyn SyscallInterceptor>) {
        self.syscall_interceptor = interceptor;
    }

    /// Load a [`LlilFunction`]'s instruction stream into the interpreter.
    ///
    /// # Errors
    /// Returns [`InterpError::DuplicateAddress`] if two instructions share the
    /// same address (mirroring the verifier's duplicate-address check); the
    /// interpreter is left empty in that case.
    pub fn load_function(&mut self, func: &LlilFunction) -> Result<(), InterpError> {
        self.instructions.clear();
        self.order.clear();
        for annotated in &func.instructions {
            if self
                .instructions
                .insert(annotated.address.0, annotated.instr.clone())
                .is_some()
            {
                let addr = annotated.address.0;
                self.instructions.clear();
                self.order.clear();
                return Err(InterpError::DuplicateAddress(addr));
            }
            self.order.push(annotated.address.0);
        }
        self.order.sort_unstable();
        // Set PC to the first instruction.
        if let Some(&first) = self.order.first() {
            self.cpu.pc = first;
            self.pc_index = 0;
            self.halted = false;
        } else {
            // Empty function: nothing to execute, halt cleanly instead of
            // stepping at a stale PC.
            self.halted = true;
        }
        Ok(())
    }

    /// Execute one instruction at the current PC.
    ///
    /// # Errors
    /// Returns an [`InterpError`] if the instruction faults (division by zero,
    /// unmapped memory access, unsupported opcode, etc.).
    pub fn step(&mut self) -> Result<StepResult, InterpError> {
        if self.halted {
            return Ok(StepResult::Returned);
        }
        if self.steps >= self.step_limit {
            return Err(InterpError::StepLimitExceeded);
        }
        self.steps += 1;

        let pc = self.cpu.pc;
        let instr = self
            .instructions
            .get(&pc)
            .ok_or(InterpError::UnmappedMemory(pc))?
            .clone();

        self.stats.instructions_executed += 1;
        let result = self.execute_instruction(&instr)?;

        // Advance PC for non-branch instructions.
        match &result {
            StepResult::Continue => {
                self.advance_pc();
            }
            StepResult::Branch { target, .. } | StepResult::Called(target) => {
                self.jump_to(*target);
            }
            StepResult::Returned | StepResult::Syscall => {}
        }

        Ok(result)
    }

    /// Run until return, error, or step limit.
    ///
    /// # Errors
    /// Returns an [`InterpError`] if any step faults, or
    /// [`InterpError::StepLimitExceeded`] if the limit is reached.
    pub fn run(&mut self) -> Result<(), InterpError> {
        loop {
            match self.step()? {
                StepResult::Returned => return Ok(()),
                StepResult::Continue
                | StepResult::Branch { .. }
                | StepResult::Called(_)
                | StepResult::Syscall => {}
            }
        }
    }

    // --- private helpers ---

    fn advance_pc(&mut self) {
        let next = self.pc_index + 1;
        if next < self.order.len() {
            self.pc_index = next;
            self.cpu.pc = self.order[self.pc_index];
        } else {
            // Fell off the end of the function: halt cleanly instead of
            // re-executing the last instruction forever.
            self.halted = true;
        }
    }

    fn jump_to(&mut self, target: u64) {
        self.cpu.pc = target;
        if let Some(pos) = self.order.iter().position(|&a| a == target) {
            self.pc_index = pos;
        }
    }

    fn execute_instruction(&mut self, instr: &LlilInstruction) -> Result<StepResult, InterpError> {
        match instr {
            LlilInstruction::Nop | LlilInstruction::Breakpoint => Ok(StepResult::Continue),

            LlilInstruction::SetReg { dest, value: src, size } => self.exec_set_reg(dest, src, *size),

            LlilInstruction::SetRegSplit { high, low, src } => {
                let val = self.eval_expr(src)?;
                let lo = val;
                let hi = (val >> 63) & 0x1; // simplified
                let hi_name = Self::reg_name(high);
                let lo_name = Self::reg_name(low);
                self.cpu.write_reg_aliased(&hi_name, hi);
                self.cpu.write_reg_aliased(&lo_name, lo);
                Ok(StepResult::Continue)
            }

            LlilInstruction::Load { dest, addr, size } => {
                let a = self.eval_expr(addr)?;
                let val = self.mem.read(a, *size)?;
                self.stats.memory_reads += 1;
                let name = Self::reg_name(dest);
                self.cpu.write_reg_aliased(&name, val);
                Ok(StepResult::Continue)
            }

            LlilInstruction::Store { addr, value: src, size } => self.exec_store(addr, src, *size),

            LlilInstruction::SetFlag { name: flag, src } => {
                let val = self.eval_expr(src)?;
                self.cpu.write_flag(flag, val & 1);
                self.stats.flag_writes += 1;
                Ok(StepResult::Continue)
            }

            LlilInstruction::Push { src, size } => {
                let val = self.eval_expr(src)?;
                self.cpu.sp = self.cpu.sp.wrapping_sub(size.bytes() as u64);
                self.mem.write(self.cpu.sp, val, *size);
                self.stats.memory_writes += 1;
                Ok(StepResult::Continue)
            }

            LlilInstruction::Pop { dest, size } => self.exec_pop(dest, *size),

            LlilInstruction::JumpDest { dest }
            | LlilInstruction::Jump(dest)
            | LlilInstruction::JumpTo { dest, .. } => {
                let target = self.eval_expr(dest)?;
                Ok(StepResult::Branch {
                    taken: true,
                    target,
                })
            }

            LlilInstruction::ConditionalJump { cond, true_target, false_target } => self.exec_conditional_jump(cond, *true_target, *false_target),

            LlilInstruction::SetRegister { dest, value, size } => {
                let val = self.eval_expr(value)?;
                let name = format!("r{dest}");
                self.cpu.write_reg_aliased(&name, CpuState::mask(val, *size));
                Ok(StepResult::Continue)
            }

            LlilInstruction::CallDest { dest } | LlilInstruction::Call(dest) => self.exec_call(dest),

            LlilInstruction::TailCall { dest } => {
                let target = self.eval_expr(dest)?;
                Ok(StepResult::Called(target))
            }

            LlilInstruction::Ret | LlilInstruction::Return { .. } => Ok(StepResult::Returned),
            LlilInstruction::CondJump { cond, true_dest, false_dest } => self.exec_cond_jump(cond, *true_dest, *false_dest),
            LlilInstruction::CondCall { cond, dest } => self.exec_cond_call(cond, dest),
            LlilInstruction::Trap { .. } => Err(InterpError::UnsupportedInstruction("Trap".into())),
            LlilInstruction::SysCall => self.exec_syscall(),
            LlilInstruction::Intrinsic { name, .. } => Err(InterpError::UnknownIntrinsic(name.clone())),
            LlilInstruction::Undefined => Err(InterpError::UndefinedValue),
            LlilInstruction::Unimplemented { .. } | LlilInstruction::UnimplementedRaw { .. } => {
                Err(InterpError::UnsupportedInstruction("Unimplemented".into()))
            }
        }
    }

    fn exec_cond_jump(&mut self, cond: &LlilExpr, true_dest: Address, false_dest: Address) -> Result<StepResult, InterpError> {
        let cval = self.eval_expr(cond)?;
        if cval != 0 {
            self.stats.branches_taken += 1;
            Ok(StepResult::Branch { taken: true, target: true_dest.0 })
        } else {
            self.stats.branches_not_taken += 1;
            Ok(StepResult::Branch { taken: false, target: false_dest.0 })
        }
    }

    fn exec_cond_call(&mut self, cond: &LlilExpr, dest: &LlilExpr) -> Result<StepResult, InterpError> {
        let cval = self.eval_expr(cond)?;
        if cval != 0 {
            let target = self.eval_expr(dest)?;
            Ok(StepResult::Called(target))
        } else {
            Ok(StepResult::Continue)
        }
    }

    fn exec_set_reg(&mut self, dest: &LlilRegister, src: &LlilExpr, size: Size) -> Result<StepResult, InterpError> {
        let val = self.eval_expr(src)?;
        let masked = CpuState::mask(val, size);
        match dest {
            LlilRegister::Concrete(n) => self.cpu.write_reg_aliased(n, masked),
            LlilRegister::Temporary(n) => {
                self.cpu.write_reg_aliased(&format!("tmp{n}"), masked);
            }
        }
        Ok(StepResult::Continue)
    }

    fn exec_store(&mut self, addr: &LlilExpr, src: &LlilExpr, size: Size) -> Result<StepResult, InterpError> {
        let a = self.eval_expr(addr)?;
        let val = self.eval_expr(src)?;
        self.mem.write(a, val, size);
        self.stats.memory_writes += 1;
        Ok(StepResult::Continue)
    }

    fn exec_pop(&mut self, dest: &LlilRegister, size: Size) -> Result<StepResult, InterpError> {
        if self.cpu.sp == 0 {
            return Err(InterpError::StackUnderflow);
        }
        let val = self.mem.read(self.cpu.sp, size)?;
        self.stats.memory_reads += 1;
        self.cpu.sp = self.cpu.sp.wrapping_add(size.bytes() as u64);
        self.cpu.write_reg_aliased(&Self::reg_name(dest), val);
        Ok(StepResult::Continue)
    }

    fn exec_conditional_jump(&mut self, cond: &LlilExpr, true_target: Address, false_target: Address) -> Result<StepResult, InterpError> {
        if self.eval_expr(cond)? != 0 {
            Ok(StepResult::Branch { taken: true, target: true_target.0 })
        } else {
            Ok(StepResult::Branch { taken: false, target: false_target.0 })
        }
    }

    fn exec_call(&mut self, dest: &LlilExpr) -> Result<StepResult, InterpError> {
        let target = self.eval_expr(dest)?;
        let ret_addr = self.cpu.pc.wrapping_add(1);
        let ptr = self.cpu.ptr_size_variant();
        self.cpu.sp = self.cpu.sp.wrapping_sub(ptr.bytes() as u64);
        self.mem.write(self.cpu.sp, ret_addr, ptr);
        Ok(StepResult::Called(target))
    }

    fn exec_syscall(&mut self) -> Result<StepResult, InterpError> {
        self.stats.syscalls += 1;
        let mut interceptor = std::mem::replace(&mut self.syscall_interceptor, Box::new(NullInterceptor));
        let res = interceptor.handle(self);
        self.syscall_interceptor = interceptor;
        res.map(|()| StepResult::Syscall)
    }

    fn eval_expr(&mut self, expr: &LlilExpr) -> Result<u64, InterpError> {
        // Guard against stack overflow from adversarially-nested expression trees.
        self.expr_depth += 1;
        if self.expr_depth > MAX_EXPR_DEPTH {
            self.expr_depth -= 1;
            return Err(InterpError::UnsupportedInstruction(
                "expression tree exceeds maximum nesting depth".into(),
            ));
        }
        let result = self.eval_expr_inner(expr);
        self.expr_depth -= 1;
        result
    }

    fn eval_arith_inner(&mut self, expr: &LlilExpr) -> Result<u64, InterpError> {
        match expr {
            LlilExpr::AddT(l, r, s) | LlilExpr::Add { left: l, right: r, size: s } => {
                Ok(CpuState::mask(self.eval_expr(l)?.wrapping_add(self.eval_expr(r)?), *s))
            }
            LlilExpr::SubT(l, r, s) | LlilExpr::Sub { left: l, right: r, size: s } => {
                Ok(CpuState::mask(self.eval_expr(l)?.wrapping_sub(self.eval_expr(r)?), *s))
            }
            LlilExpr::MulT(l, r, s) | LlilExpr::Mul { left: l, right: r, size: s } => {
                Ok(CpuState::mask(self.eval_expr(l)?.wrapping_mul(self.eval_expr(r)?), *s))
            }
            LlilExpr::DivU(l, r, s) => {
                let rv = self.eval_expr(r)?;
                if rv == 0 { return Err(InterpError::DivisionByZero); }
                Ok(CpuState::mask(self.eval_expr(l)? / rv, *s))
            }
            LlilExpr::DivS(l, r, s) => {
                let rv = (self.eval_expr(r)?).cast_signed();
                if rv == 0 { return Err(InterpError::DivisionByZero); }
                let lv = (self.eval_expr(l)?).cast_signed();
                Ok(CpuState::mask(lv.checked_div(rv).unwrap_or(i64::MAX).cast_unsigned(), *s))
            }
            LlilExpr::ModU(l, r, s) => {
                let rv = self.eval_expr(r)?;
                if rv == 0 { return Err(InterpError::DivisionByZero); }
                Ok(CpuState::mask(self.eval_expr(l)? % rv, *s))
            }
            LlilExpr::ModS(l, r, s) => {
                let rv = (self.eval_expr(r)?).cast_signed();
                if rv == 0 { return Err(InterpError::DivisionByZero); }
                let lv = (self.eval_expr(l)?).cast_signed();
                Ok(CpuState::mask(lv.checked_rem(rv).unwrap_or(0).cast_unsigned(), *s))
            }
            LlilExpr::Neg(e, s) => Ok(CpuState::mask(self.eval_expr(e)?.wrapping_neg(), *s)),
            LlilExpr::And(l, r, s) => Ok(CpuState::mask(self.eval_expr(l)? & self.eval_expr(r)?, *s)),
            LlilExpr::Or(l, r, s)  => Ok(CpuState::mask(self.eval_expr(l)? | self.eval_expr(r)?, *s)),
            LlilExpr::Xor(l, r, s) => Ok(CpuState::mask(self.eval_expr(l)? ^ self.eval_expr(r)?, *s)),
            LlilExpr::Not(e, s) => Ok(CpuState::mask(!self.eval_expr(e)?, *s)),
            _ => unreachable!("eval_arith_inner: unexpected expr"),
        }
    }

    fn eval_shift_inner(&mut self, expr: &LlilExpr) -> Result<u64, InterpError> {
        match expr {
            LlilExpr::ShlT(l, r, s) | LlilExpr::Shl { value: l, shift: r, size: s } => {
                Ok(CpuState::mask(self.eval_expr(l)? << (self.eval_expr(r)? & 63), *s))
            }
            LlilExpr::Shr(l, r, s) => {
                Ok(CpuState::mask(self.eval_expr(l)? >> (self.eval_expr(r)? & 63), *s))
            }
            LlilExpr::Sar(l, r, s) => {
                // Sign-extend the operand-width value to i64 FIRST, so the
                // arithmetic shift brings in copies of the TRUE sign bit. A
                // sub-64-bit negative (e.g. 0x8000_0000 as i32) sits in the
                // u64 as a positive bit pattern; casting it straight to i64
                // shifted in zeros. Shifting it up to the top of the word and
                // back down (arithmetically) does the sign extension and also
                // discards any garbage in the high bits.
                let bits = s.bytes() * 8;
                let raw = self.eval_expr(l)?;
                let lv = if bits >= 64 {
                    raw.cast_signed()
                } else {
                    let up = (64 - bits) as u32;
                    (raw << up).cast_signed() >> up
                };
                Ok(CpuState::mask((lv >> (self.eval_expr(r)? & 63)).cast_unsigned(), *s))
            }
            LlilExpr::Rol(l, r, s) => {
                let bits = u32::try_from(s.bytes() * 8).unwrap_or(64);
                let shift = u32::try_from(self.eval_expr(r)? & 0xFFFF_FFFF).unwrap_or(0) % bits;
                let lv = self.eval_expr(l)?;
                let res = if shift == 0 { lv } else { (lv << shift) | (lv >> (bits - shift)) };
                Ok(CpuState::mask(res, *s))
            }
            LlilExpr::Ror(l, r, s) => {
                let bits = u32::try_from(s.bytes() * 8).unwrap_or(64);
                let shift = u32::try_from(self.eval_expr(r)? & 0xFFFF_FFFF).unwrap_or(0) % bits;
                let lv = self.eval_expr(l)?;
                let res = if shift == 0 { lv } else { (lv >> shift) | (lv << (bits - shift)) };
                Ok(CpuState::mask(res, *s))
            }
            _ => unreachable!("eval_shift_inner: unexpected expr"),
        }
    }

    fn eval_expr_inner(&mut self, expr: &LlilExpr) -> Result<u64, InterpError> {
        match expr {
            LlilExpr::Const { value, .. } => Ok(*value),
            LlilExpr::RegisterRef { reg, size } => {
                let val = match reg {
                    LlilRegister::Concrete(n) => self.cpu.read_reg_aliased(n),
                    LlilRegister::Temporary(n) => self.cpu.read_reg_aliased(&format!("tmp{n}")),
                };
                Ok(CpuState::mask(val, *size))
            }
            LlilExpr::Register { id, size } => {
                Ok(CpuState::mask(self.cpu.read_reg_aliased(&format!("r{id}")), *size))
            }
            LlilExpr::Load { addr, size } => {
                let a = self.eval_expr(addr)?;
                self.stats.memory_reads += 1;
                self.mem.read(a, *size)
            }
            LlilExpr::AddT(..) | LlilExpr::Add { .. } | LlilExpr::SubT(..) | LlilExpr::Sub { .. }
            | LlilExpr::MulT(..) | LlilExpr::Mul { .. } | LlilExpr::DivU(..) | LlilExpr::DivS(..)
            | LlilExpr::ModU(..) | LlilExpr::ModS(..) | LlilExpr::Neg(..)
            | LlilExpr::And(..) | LlilExpr::Or(..) | LlilExpr::Xor(..) | LlilExpr::Not(..) => {
                self.eval_arith_inner(expr)
            }
            LlilExpr::ShlT(..) | LlilExpr::Shl { .. } | LlilExpr::Shr(..) | LlilExpr::Sar(..)
            | LlilExpr::Rol(..) | LlilExpr::Ror(..) => self.eval_shift_inner(expr),
            // Comparisons → 0 or 1
            LlilExpr::CmpEq(l, r) => Ok(u64::from(self.eval_expr(l)? == self.eval_expr(r)?)),
            LlilExpr::CmpNe(l, r) => Ok(u64::from(self.eval_expr(l)? != self.eval_expr(r)?)),
            LlilExpr::CmpUlt(l, r) => Ok(u64::from(self.eval_expr(l)? < self.eval_expr(r)?)),
            LlilExpr::CmpUle(l, r) => Ok(u64::from(self.eval_expr(l)? <= self.eval_expr(r)?)),
            LlilExpr::CmpUgt(l, r) => Ok(u64::from(self.eval_expr(l)? > self.eval_expr(r)?)),
            LlilExpr::CmpUge(l, r) => Ok(u64::from(self.eval_expr(l)? >= self.eval_expr(r)?)),
            LlilExpr::CmpSlt(l, r) => Ok(u64::from(
                (self.eval_expr(l)?).cast_signed() < (self.eval_expr(r)?).cast_signed())),
            LlilExpr::CmpSle(l, r) => Ok(u64::from(
                (self.eval_expr(l)?).cast_signed() <= (self.eval_expr(r)?).cast_signed())),
            LlilExpr::CmpSgt(l, r) => Ok(u64::from(
                (self.eval_expr(l)?).cast_signed() > (self.eval_expr(r)?).cast_signed())),
            LlilExpr::CmpSge(l, r) => Ok(u64::from(
                (self.eval_expr(l)?).cast_signed() >= (self.eval_expr(r)?).cast_signed())),
            LlilExpr::ZeroExtend { expr, .. } => self.eval_expr(expr),
            LlilExpr::SignExtend { expr, from, to } => {
                let v = self.eval_expr(expr)?;
                let bits = from.bits() as u64;
                let extended = if (v >> (bits - 1)) & 1 == 0 {
                    v
                } else {
                    let mask = if bits >= 64 { 0u64 } else { !((1u64 << bits) - 1) };
                    v | mask
                };
                Ok(CpuState::mask(extended, *to))
            }
            LlilExpr::LowPart { expr, to } => Ok(CpuState::mask(self.eval_expr(expr)?, *to)),
            // Float ops — simplified: treat as integer passthrough
            LlilExpr::FAdd(l, r, _) | LlilExpr::FSub(l, r, _) | LlilExpr::FMul(l, r, _)
            | LlilExpr::FDiv(l, r, _) | LlilExpr::FCmpEq(l, r)
            | LlilExpr::FCmpLt(l, r) | LlilExpr::FCmpGt(l, r) => {
                let _ = self.eval_expr(l)?;
                let _ = self.eval_expr(r)?;
                Ok(0)
            }
            LlilExpr::FNeg(e, _) => { let _ = self.eval_expr(e)?; Ok(0) }
            LlilExpr::IntToFloat { expr, .. } | LlilExpr::FloatToInt { expr, .. } => {
                self.eval_expr(expr)
            }
            LlilExpr::StackPointer(_) => Ok(self.cpu.sp),
            LlilExpr::Flag(name) => Ok(self.cpu.read_flag(name)),
            LlilExpr::CondExpr { cond, true_val, false_val, .. } => {
                if self.eval_expr(cond)? != 0 { self.eval_expr(true_val) } else { self.eval_expr(false_val) }
            }
            LlilExpr::Undefined(_) => Err(InterpError::UndefinedValue),
            LlilExpr::Intrinsic { name, .. } => Err(InterpError::UnknownIntrinsic(name.clone())),
        }
    }

    fn reg_name(reg: &LlilRegister) -> String {
        match reg {
            LlilRegister::Concrete(n) => n.clone(),
            LlilRegister::Temporary(n) => format!("tmp{n}"),
        }
    }
}

// ---------------------------------------------------------------------------
// ExecutionTrace
// ---------------------------------------------------------------------------

/// Records the sequence of addresses visited during execution (for debugging
/// and coverage analysis).
///
/// The internal buffer uses a `VecDeque` to make the bounded-capacity eviction
/// O(1) instead of O(n).  When `max_len` is zero the trace silently discards
/// all entries, preventing unbounded memory growth on long-running executions.
#[derive(Debug, Clone, Default)]
pub struct ExecutionTrace {
    addresses: std::collections::VecDeque<u64>,
    max_len: usize,
}

impl ExecutionTrace {
    /// Create a trace with the given capacity.
    ///
    /// If `max_len` is zero every call to [`record`] is a no-op — nothing is
    /// stored — which avoids unbounded memory growth.
    #[must_use]
    pub const fn new(max_len: usize) -> Self {
        Self {
            addresses: std::collections::VecDeque::new(),
            max_len,
        }
    }

    /// Append `addr` to the trace.
    ///
    /// When the buffer is full the oldest entry is evicted in O(1).
    /// When `max_len` is zero the call is a no-op.
    pub fn record(&mut self, addr: u64) {
        if self.max_len == 0 {
            return; // unbounded recording disabled
        }
        if self.addresses.len() >= self.max_len {
            self.addresses.pop_front(); // O(1) on VecDeque, was O(n) on Vec
        }
        self.addresses.push_back(addr);
    }

    /// All recorded addresses in visit order (oldest first).
    ///
    /// Returns a `Vec` so callers see a contiguous slice; the internal ring
    /// buffer may be non-contiguous.  For hot paths prefer iterating directly.
    #[must_use]
    pub fn addresses(&self) -> Vec<u64> {
        self.addresses.iter().copied().collect()
    }

    /// Whether `addr` was ever visited.
    #[must_use]
    pub fn visited(&self, addr: u64) -> bool {
        self.addresses.contains(&addr)
    }

    /// Clear the trace.
    pub fn clear(&mut self) {
        self.addresses.clear();
    }
}

// ---------------------------------------------------------------------------
// MemoryRegion / MemoryMap helpers
// ---------------------------------------------------------------------------

/// Description of a mapped memory region.
#[derive(Debug, Clone)]
pub struct MemoryRegion {
    pub base: u64,
    pub size: usize,
    pub name: String,
    pub writable: bool,
}

impl MemoryRegion {
    #[must_use]
    pub fn new(base: u64, size: usize, name: impl Into<String>, writable: bool) -> Self {
        Self {
            base,
            size,
            name: name.into(),
            writable,
        }
    }

    /// Whether `addr` falls within this region.
    #[must_use]
    pub const fn contains(&self, addr: u64) -> bool {
        addr >= self.base && addr < self.base.saturating_add(self.size as u64)
    }

    /// End address (exclusive).
    #[must_use]
    pub const fn end(&self) -> u64 {
        self.base.saturating_add(self.size as u64)
    }
}

/// A multi-region memory map that can be used to pre-populate [`MemoryState`].
#[derive(Debug, Default)]
pub struct MemoryMap {
    pub regions: Vec<MemoryRegion>,
}

impl MemoryMap {
    /// Add a region to the map.
    pub fn add(&mut self, region: MemoryRegion) {
        self.regions.push(region);
    }

    /// Look up the region covering `addr`.
    #[must_use]
    pub fn region_at(&self, addr: u64) -> Option<&MemoryRegion> {
        self.regions.iter().find(|r| r.contains(addr))
    }

    /// Maximum bytes allowed for a single region in `apply_to`.
    /// Guards against a crafted binary mapping hundreds of MiB in one shot.
    pub const MAX_REGION_BYTES: usize = 256 * 1024 * 1024; // 256 MiB

    /// Apply all regions to `mem`, zero-filling their data.
    ///
    /// Regions larger than [`Self::MAX_REGION_BYTES`] are silently truncated
    /// to prevent DOS via memory exhaustion when processing untrusted input.
    pub fn apply_to(&self, mem: &mut MemoryState) {
        let max_size = self
            .regions
            .iter()
            .map(|r| r.size.min(Self::MAX_REGION_BYTES))
            .max()
            .unwrap_or(0);
        let zeros = vec![0u8; max_size];
        for region in &self.regions {
            let clamped = region.size.min(Self::MAX_REGION_BYTES);
            mem.map(region.base, &zeros[..clamped]);
        }
    }
}

// ---------------------------------------------------------------------------
// RegisterFile helpers
// ---------------------------------------------------------------------------

/// Snapshot of a [`CpuState`]'s register file at a given point.
#[derive(Debug, Clone, Default)]
pub struct RegisterSnapshot {
    pub registers: std::collections::HashMap<String, u64>,
    pub flags: std::collections::HashMap<String, u64>,
    pub pc: u64,
    pub sp: u64,
}

impl RegisterSnapshot {
    /// Take a snapshot of `cpu`.
    #[must_use]
    pub fn of(cpu: &CpuState) -> Self {
        Self {
            registers: cpu.registers.clone(),
            flags: cpu.flags.clone(),
            pc: cpu.pc,
            sp: cpu.sp,
        }
    }

    /// Compare two snapshots; returns names of registers that differ.
    #[must_use] 
    pub fn diff<'a>(&'a self, other: &'a Self) -> Vec<&'a str> {
        let mut diffs = Vec::new();
        for (name, &val) in &self.registers {
            if other.registers.get(name) != Some(&val) {
                diffs.push(name.as_str());
            }
        }
        diffs
    }
}

// ---------------------------------------------------------------------------
// WatchPoint
// ---------------------------------------------------------------------------

/// A watchpoint that triggers when a memory address is read or written.
#[derive(Debug, Clone)]
pub struct WatchPoint {
    pub address: u64,
    pub on_read: bool,
    pub on_write: bool,
    pub hit_count: usize,
}

impl WatchPoint {
    #[must_use]
    pub const fn read_write(address: u64) -> Self {
        Self {
            address,
            on_read: true,
            on_write: true,
            hit_count: 0,
        }
    }

    #[must_use]
    pub const fn write_only(address: u64) -> Self {
        Self {
            address,
            on_read: false,
            on_write: true,
            hit_count: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// InterpreterBuilder — fluent builder for LlilInterpreter
// ---------------------------------------------------------------------------

/// Fluent builder for constructing a configured [`LlilInterpreter`].
pub struct InterpreterBuilder {
    ptr_size: usize,
    step_limit: u64,
    lenient: bool,
    stack_base: u64,
    stack_size: usize,
}

impl InterpreterBuilder {
    /// Create a builder for a 64-bit target.
    #[must_use]
    pub const fn x64() -> Self {
        Self {
            ptr_size: 8,
            step_limit: 1_000_000,
            lenient: false,
            stack_base: 0x7fff_0000,
            stack_size: 0x10000,
        }
    }

    /// Create a builder for a 32-bit target.
    #[must_use]
    pub const fn x86() -> Self {
        Self {
            ptr_size: 4,
            step_limit: 1_000_000,
            lenient: false,
            stack_base: 0xbfff_0000,
            stack_size: 0x10000,
        }
    }

    /// Set a custom step limit.
    #[must_use]
    pub const fn step_limit(mut self, limit: u64) -> Self {
        self.step_limit = limit;
        self
    }

    /// Allow lenient memory reads (return 0 for unmapped addresses).
    #[must_use]
    pub const fn lenient(mut self) -> Self {
        self.lenient = true;
        self
    }

    /// Build the interpreter.
    #[must_use]
    pub fn build(self) -> LlilInterpreter {
        let cpu = CpuState::new(self.ptr_size);
        let mut mem = if self.lenient {
            MemoryState::lenient()
        } else {
            MemoryState::new()
        };
        mem.map(self.stack_base, &vec![0u8; self.stack_size]);
        let mut interp = LlilInterpreter::new(cpu, mem);
        interp.step_limit = self.step_limit;
        interp.cpu.sp = self.stack_base + self.stack_size as u64 / 2;
        interp
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{LlilAnnotatedInstr, LlilFunction, Size};

    fn make_func(instrs: Vec<(u64, LlilInstruction)>) -> LlilFunction {
        let instructions = instrs
            .into_iter()
            .map(|(addr, instr)| LlilAnnotatedInstr {
                address: Address(addr),
                size: 1,
                instr,
                length: 1,
            })
            .collect();
        let mut f = LlilFunction::new(Address(0));
        f.name = Some("test".into());
        f.instructions = instructions;
        f
    }

    fn make_interp(ptr_size: usize) -> LlilInterpreter {
        let cpu = CpuState::new(ptr_size);
        let mem = MemoryState::lenient();
        LlilInterpreter::new(cpu, mem)
    }

    // --- MemoryState tests ---

    #[test]
    fn mem_write_read_byte() {
        let mut m = MemoryState::new();
        m.map(0x1000, &[0xAB, 0xCD]);
        assert_eq!(m.read(0x1000, Size::Byte).unwrap(), 0xAB);
        assert_eq!(m.read(0x1001, Size::Byte).unwrap(), 0xCD);
    }

    #[test]
    fn mem_write_read_dword_le() {
        let mut m = MemoryState::new();
        m.write(0x2000, 0xDEAD_BEEF, Size::DWord);
        assert_eq!(m.read(0x2000, Size::DWord).unwrap(), 0xDEAD_BEEF);
    }

    #[test]
    fn mem_unmapped_returns_error() {
        let m = MemoryState::new();
        assert!(matches!(
            m.read(0xBAD0, Size::Byte),
            Err(InterpError::UnmappedMemory(_))
        ));
    }

    #[test]
    fn mem_lenient_unmapped_returns_zero() {
        let m = MemoryState::lenient();
        assert_eq!(m.read(0xBAD0, Size::Byte).unwrap(), 0);
    }

    #[test]
    fn mem_read_write_never_wrap_address_space() {
        // map() truncates at u64::MAX; read/write must be consistent and never
        // wrap to address 0.
        let mut m = MemoryState::new();
        m.map(0, &[0x11, 0x22, 0x33, 0x44]);
        m.map(u64::MAX - 1, &[0xAA, 0xBB]);

        // Write straddling u64::MAX: only the first two bytes land, page 0 untouched.
        m.write(u64::MAX - 1, 0xDDCC_BBAA, Size::DWord);
        assert_eq!(m.read(u64::MAX - 1, Size::Byte).unwrap(), 0xAA);
        assert_eq!(m.read(u64::MAX, Size::Byte).unwrap(), 0xBB);
        assert_eq!(m.read(0, Size::DWord).unwrap(), 0x4433_2211);

        // Strict read straddling u64::MAX errors instead of wrapping to addr 0.
        assert!(matches!(
            m.read(u64::MAX - 1, Size::DWord),
            Err(InterpError::UnmappedMemory(_))
        ));
    }

    #[test]
    fn mem_lenient_read_past_u64_max_is_zero() {
        let mut m = MemoryState::lenient();
        m.map(u64::MAX - 1, &[0xAA, 0xBB]);
        // Bytes past u64::MAX read as zero in lenient mode; no wrap to page 0.
        assert_eq!(m.read(u64::MAX - 1, Size::DWord).unwrap(), 0x0000_BBAA);
    }

    #[test]
    fn mem_read_across_page_boundary() {
        let mut m = MemoryState::new();
        // 0x0FFE..0x1002 spans two 4 KiB pages.
        m.map(0x0FFE, &[0x11, 0x22, 0x33, 0x44]);
        assert_eq!(m.read(0x0FFE, Size::DWord).unwrap(), 0x4433_2211);
    }

    #[test]
    fn mem_qword_roundtrip() {
        let mut m = MemoryState::new();
        m.write(0x1000, 0x0102_0304_0506_0708, Size::QWord);
        assert_eq!(m.read(0x1000, Size::QWord).unwrap(), 0x0102_0304_0506_0708);
    }

    #[test]
    fn mem_mapped_bytes_count() {
        let mut m = MemoryState::new();
        m.map(0x1000, &[1u8; 8]);
        assert!(m.mapped_bytes() > 0);
    }

    // --- CpuState tests ---

    #[test]
    fn cpu_read_unknown_reg_zero() {
        let cpu = CpuState::new(8);
        assert_eq!(cpu.read_reg("rax"), 0);
    }

    #[test]
    fn cpu_write_read_reg() {
        let mut cpu = CpuState::new(8);
        cpu.write_reg("rbx", 0xDEAD);
        assert_eq!(cpu.read_reg("rbx"), 0xDEAD);
    }

    // --- CpuState sub-register aliasing (opt-in, additive: read_reg/write_reg
    // above are untouched, these are new alias-aware methods) ---

    #[test]
    fn cpu_alias_compose_al_ah_into_ax() {
        // pack_fields-style witness: write the low byte, then the high byte,
        // then read the composed 16-bit register.
        let mut cpu = CpuState::new(8);
        cpu.write_reg_aliased("al", 0xA1);
        cpu.write_reg_aliased("ah", 0x1E);
        assert_eq!(cpu.read_reg_aliased("ax"), 0x1EA1);
    }

    #[test]
    fn cpu_alias_eax_write_zero_extends_rax() {
        // x86-64: writing a 32-bit register zero-extends the full 64-bit
        // parent (unlike 8/16-bit writes, which leave the upper bits alone).
        let mut cpu = CpuState::new(8);
        cpu.write_reg_aliased("rax", 0xFFFF_FFFF_0000_0000);
        cpu.write_reg_aliased("eax", 0x1234_5678);
        assert_eq!(cpu.read_reg_aliased("rax"), 0x1234_5678);
    }

    #[test]
    fn cpu_alias_al_write_does_not_zero_extend() {
        // 8/16-bit writes are NOT zero-extended — they must leave the rest
        // of the parent register untouched (AMD APM).
        let mut cpu = CpuState::new(8);
        cpu.write_reg_aliased("rax", 0x1122_3344_5566_7788);
        cpu.write_reg_aliased("al", 0xFF);
        assert_eq!(cpu.read_reg_aliased("rax"), 0x1122_3344_5566_77FF);
    }

    #[test]
    fn cpu_alias_ah_write_does_not_zero_extend() {
        let mut cpu = CpuState::new(8);
        cpu.write_reg_aliased("rax", 0x1122_3344_5566_7788);
        cpu.write_reg_aliased("ah", 0xFF);
        assert_eq!(cpu.read_reg_aliased("rax"), 0x1122_3344_5566_FF88);
    }

    #[test]
    fn cpu_alias_read_narrow_extracts_from_wide() {
        let mut cpu = CpuState::new(8);
        cpu.write_reg_aliased("rcx", 0x1122_3344_5566_7788);
        assert_eq!(cpu.read_reg_aliased("ecx"), 0x5566_7788);
        assert_eq!(cpu.read_reg_aliased("cx"), 0x7788);
        assert_eq!(cpu.read_reg_aliased("cl"), 0x88);
        assert_eq!(cpu.read_reg_aliased("ch"), 0x77);
    }

    #[test]
    fn cpu_alias_extended_regs_r8_family() {
        // r8b/r8w/r8d/r8 (no legacy high-byte form) must alias the same way.
        let mut cpu = CpuState::new(8);
        cpu.write_reg_aliased("r8", 0x1122_3344_5566_7788);
        cpu.write_reg_aliased("r8b", 0xFF);
        assert_eq!(cpu.read_reg_aliased("r8"), 0x1122_3344_5566_77FF);
        cpu.write_reg_aliased("r8d", 0xAABB_CCDD);
        assert_eq!(cpu.read_reg_aliased("r8"), 0xAABB_CCDD); // 32-bit write zero-extends
    }

    #[test]
    fn cpu_alias_unrelated_names_are_independent() {
        // Non-x86-GPR names (other architectures, temporaries) fall back to
        // plain by-name storage exactly like the existing read_reg/write_reg.
        let mut cpu = CpuState::new(8);
        cpu.write_reg_aliased("x0", 5);
        cpu.write_reg_aliased("tmp0", 9);
        assert_eq!(cpu.read_reg_aliased("x0"), 5);
        assert_eq!(cpu.read_reg_aliased("tmp0"), 9);
    }

    #[test]
    fn cpu_alias_read_reg_and_write_reg_are_unaffected() {
        // The pre-existing plain API must stay byte-identical: it does NOT
        // go through the alias table, so writing "al" through the OLD API
        // must NOT be visible through "ax" (that's exactly the bug the new
        // opt-in API fixes, without changing the old one's behaviour).
        let mut cpu = CpuState::new(8);
        cpu.write_reg("al", 0xFF);
        assert_eq!(cpu.read_reg("ax"), 0);
        assert_eq!(cpu.read_reg("al"), 0xFF);
    }

    #[test]
    fn cpu_mask_byte() {
        assert_eq!(CpuState::mask(0x1234, Size::Byte), 0x34);
    }

    #[test]
    fn cpu_mask_word() {
        assert_eq!(CpuState::mask(0x1234_5678, Size::Word), 0x5678);
    }

    #[test]
    fn cpu_mask_dword() {
        assert_eq!(
            CpuState::mask(0xFFFF_FFFF_1234_5678, Size::DWord),
            0x1234_5678
        );
    }

    #[test]
    fn cpu_flag_roundtrip() {
        let mut cpu = CpuState::new(8);
        cpu.write_flag("zero", 1);
        assert_eq!(cpu.read_flag("zero"), 1);
        cpu.write_flag("zero", 0);
        assert_eq!(cpu.read_flag("zero"), 0);
    }

    #[test]
    fn cpu_apply_flags() {
        let mut cpu = CpuState::new(8);
        cpu.apply_flags(&[FlagUpdate::set("carry"), FlagUpdate::clear("zero")]);
        assert_eq!(cpu.read_flag("carry"), 1);
        assert_eq!(cpu.read_flag("zero"), 0);
    }

    #[test]
    fn cpu_ptr_size_variant_64() {
        let cpu = CpuState::new(8);
        assert_eq!(cpu.ptr_size_variant(), Size::QWord);
    }

    #[test]
    fn cpu_ptr_size_variant_32() {
        let cpu = CpuState::new(4);
        assert_eq!(cpu.ptr_size_variant(), Size::DWord);
    }

    // --- FlagUpdate tests ---

    #[test]
    fn flag_update_set() {
        let f = FlagUpdate::set("carry");
        assert_eq!(f.value, 1);
    }

    #[test]
    fn flag_update_clear() {
        let f = FlagUpdate::clear("carry");
        assert_eq!(f.value, 0);
    }

    // --- InterpreterStats tests ---

    #[test]
    fn stats_total_branches() {
        let s = InterpreterStats {
            branches_taken: 3,
            branches_not_taken: 7,
            ..InterpreterStats::default()
        };
        assert_eq!(s.total_branches(), 10);
    }

    #[test]
    fn stats_branch_taken_rate() {
        let s = InterpreterStats {
            branches_taken: 1,
            branches_not_taken: 3,
            ..InterpreterStats::default()
        };
        assert!((s.branch_taken_rate() - 0.25).abs() < 1e-9);
    }

    #[test]
    fn stats_branch_taken_rate_no_branches() {
        let s = InterpreterStats::default();
        assert_eq!(s.branch_taken_rate(), 0.0);
    }

    // --- Interpreter execution tests ---

    #[test]
    fn exec_nop() {
        let mut interp = make_interp(8);
        let func = make_func(vec![(0, LlilInstruction::Nop)]);
        interp.load_function(&func).unwrap();
        assert_eq!(interp.step().unwrap(), StepResult::Continue);
    }

    #[test]
    fn load_function_rejects_duplicate_addresses() {
        let mut interp = make_interp(8);
        let func = make_func(vec![
            (0, LlilInstruction::Nop),
            (4, LlilInstruction::Nop),
            (4, LlilInstruction::Nop),
        ]);
        assert_eq!(
            interp.load_function(&func),
            Err(InterpError::DuplicateAddress(4))
        );
        // Interpreter must be left empty: nothing to execute.
        assert!(matches!(interp.step(), Err(InterpError::UnmappedMemory(_))));
    }

    #[test]
    fn exec_set_reg_const() {
        let mut interp = make_interp(8);
        let func = make_func(vec![(
            0,
            LlilInstruction::SetReg {
                dest: LlilRegister::Concrete("rax".into()),
                size: Size::QWord,
                value: LlilExpr::Const {
                    value: 42,
                    size: Size::QWord,
                },
            },
        )]);
        interp.load_function(&func).unwrap();
        interp.step().unwrap();
        assert_eq!(interp.cpu.read_reg("rax"), 42);
    }

    #[test]
    fn exec_add_expr() {
        let mut interp = make_interp(8);
        interp.cpu.write_reg("rax", 10);
        interp.cpu.write_reg("rbx", 20);
        let src = LlilExpr::AddT(
            Box::new(LlilExpr::RegisterRef {
                reg: LlilRegister::Concrete("rax".into()),
                size: Size::QWord,
            }),
            Box::new(LlilExpr::RegisterRef {
                reg: LlilRegister::Concrete("rbx".into()),
                size: Size::QWord,
            }),
            Size::QWord,
        );
        let func = make_func(vec![(
            0,
            LlilInstruction::SetReg {
                dest: LlilRegister::Concrete("rcx".into()),
                size: Size::QWord,
                value: src,
            },
        )]);
        interp.load_function(&func).unwrap();
        interp.step().unwrap();
        assert_eq!(interp.cpu.read_reg("rcx"), 30);
    }

    #[test]
    fn exec_store_load() {
        let mut interp = make_interp(8);
        interp.mem.map(0x1000, &[0u8; 16]);
        let store = LlilInstruction::Store {
            addr: LlilExpr::Const {
                value: 0x1000,
                size: Size::QWord,
            },
            size: Size::DWord,
            value: LlilExpr::Const {
                value: 0xDEAD_BEEF,
                size: Size::DWord,
            },
        };
        let load = LlilInstruction::Load {
            dest: LlilRegister::Concrete("rax".into()),
            addr: LlilExpr::Const {
                value: 0x1000,
                size: Size::QWord,
            },
            size: Size::DWord,
        };
        let func = make_func(vec![(0, store), (1, load)]);
        interp.load_function(&func).unwrap();
        interp.step().unwrap();
        interp.step().unwrap();
        assert_eq!(interp.cpu.read_reg("rax"), 0xDEAD_BEEF);
    }

    #[test]
    fn exec_ret() {
        let mut interp = make_interp(8);
        let func = make_func(vec![(0, LlilInstruction::Ret)]);
        interp.load_function(&func).unwrap();
        assert_eq!(interp.step().unwrap(), StepResult::Returned);
    }

    #[test]
    fn exec_cond_jump_taken() {
        let mut interp = make_interp(8);
        interp.cpu.write_reg("rax", 1);
        let func = make_func(vec![(
            0,
            LlilInstruction::CondJump {
                cond: LlilExpr::RegisterRef {
                    reg: LlilRegister::Concrete("rax".into()),
                    size: Size::Byte,
                },
                true_dest: Address(0x100),
                false_dest: Address(0x200),
            },
        )]);
        interp.load_function(&func).unwrap();
        let res = interp.step().unwrap();
        assert_eq!(
            res,
            StepResult::Branch {
                taken: true,
                target: 0x100
            }
        );
        assert_eq!(interp.stats.branches_taken, 1);
    }

    #[test]
    fn exec_cond_jump_not_taken() {
        let mut interp = make_interp(8);
        interp.cpu.write_reg("rax", 0);
        let func = make_func(vec![(
            0,
            LlilInstruction::CondJump {
                cond: LlilExpr::RegisterRef {
                    reg: LlilRegister::Concrete("rax".into()),
                    size: Size::Byte,
                },
                true_dest: Address(0x100),
                false_dest: Address(0x200),
            },
        )]);
        interp.load_function(&func).unwrap();
        let res = interp.step().unwrap();
        assert_eq!(
            res,
            StepResult::Branch {
                taken: false,
                target: 0x200
            }
        );
        assert_eq!(interp.stats.branches_not_taken, 1);
    }

    #[test]
    fn exec_div_by_zero() {
        let mut interp = make_interp(8);
        let src = LlilExpr::DivU(
            Box::new(LlilExpr::Const {
                value: 10,
                size: Size::QWord,
            }),
            Box::new(LlilExpr::Const {
                value: 0,
                size: Size::QWord,
            }),
            Size::QWord,
        );
        let func = make_func(vec![(
            0,
            LlilInstruction::SetReg {
                dest: LlilRegister::Concrete("rax".into()),
                size: Size::QWord,
                value: src,
            },
        )]);
        interp.load_function(&func).unwrap();
        assert!(matches!(interp.step(), Err(InterpError::DivisionByZero)));
    }

    #[test]
    fn exec_step_limit() {
        let mut interp = make_interp(8);
        interp.step_limit = 2;
        let func = make_func(vec![
            (0, LlilInstruction::Nop),
            (1, LlilInstruction::Nop),
            (2, LlilInstruction::Nop),
        ]);
        interp.load_function(&func).unwrap();
        interp.step().unwrap();
        interp.step().unwrap();
        assert!(matches!(interp.step(), Err(InterpError::StepLimitExceeded)));
    }

    #[test]
    fn empty_function_halts_cleanly() {
        let mut interp = make_interp(8);
        let func = make_func(vec![]);
        interp.load_function(&func).unwrap();
        // Must not read a stale PC and fault with UnmappedMemory.
        assert_eq!(interp.step().unwrap(), StepResult::Returned);
        assert!(interp.run().is_ok());
    }

    #[test]
    fn fall_off_end_halts_instead_of_looping() {
        let mut interp = make_interp(8);
        let func = make_func(vec![(0, LlilInstruction::Nop), (1, LlilInstruction::Nop)]);
        interp.load_function(&func).unwrap();
        assert_eq!(interp.step().unwrap(), StepResult::Continue);
        assert_eq!(interp.step().unwrap(), StepResult::Continue);
        // Past the last instruction: halt, do not re-execute it forever.
        assert_eq!(interp.step().unwrap(), StepResult::Returned);
        let executed = interp.stats.instructions_executed;
        assert_eq!(executed, 2);
        // run() on a fresh load must terminate, not hit the step limit.
        let mut interp2 = make_interp(8);
        let func2 = make_func(vec![(0, LlilInstruction::Nop)]);
        interp2.load_function(&func2).unwrap();
        assert!(interp2.run().is_ok());
    }

    #[test]
    fn exec_push_pop() {
        let mut interp = make_interp(8);
        interp.cpu.sp = 0x2000;
        interp.mem.map(0x1000, &[0u8; 32]);
        let push = LlilInstruction::Push {
            src: LlilExpr::Const {
                value: 0xCAFE,
                size: Size::QWord,
            },
            size: Size::QWord,
        };
        let pop = LlilInstruction::Pop {
            dest: LlilRegister::Concrete("rax".into()),
            size: Size::QWord,
        };
        let func = make_func(vec![(0, push), (1, pop)]);
        interp.load_function(&func).unwrap();
        interp.step().unwrap();
        interp.step().unwrap();
        assert_eq!(interp.cpu.read_reg("rax"), 0xCAFE);
        assert_eq!(interp.cpu.sp, 0x2000);
    }

    #[test]
    fn exec_flag_set() {
        let mut interp = make_interp(8);
        let func = make_func(vec![(
            0,
            LlilInstruction::SetFlag {
                name: "zero".into(),
                src: LlilExpr::Const {
                    value: 1,
                    size: Size::Byte,
                },
            },
        )]);
        interp.load_function(&func).unwrap();
        interp.step().unwrap();
        assert_eq!(interp.cpu.read_flag("zero"), 1);
        assert_eq!(interp.stats.flag_writes, 1);
    }

    #[test]
    fn eval_sign_extend_negative() {
        let mut interp = make_interp(8);
        let expr = LlilExpr::SignExtend {
            expr: Box::new(LlilExpr::Const {
                value: 0x80,
                size: Size::Byte,
            }),
            from: Size::Byte,
            to: Size::QWord,
        };
        let func = make_func(vec![(
            0,
            LlilInstruction::SetReg {
                dest: LlilRegister::Concrete("rax".into()),
                size: Size::QWord,
                value: expr,
            },
        )]);
        interp.load_function(&func).unwrap();
        interp.step().unwrap();
        assert_eq!(interp.cpu.read_reg("rax"), 0xFFFF_FFFF_FFFF_FF80);
    }

    #[test]
    fn eval_sign_extend_positive() {
        let mut interp = make_interp(8);
        let expr = LlilExpr::SignExtend {
            expr: Box::new(LlilExpr::Const {
                value: 0x7F,
                size: Size::Byte,
            }),
            from: Size::Byte,
            to: Size::QWord,
        };
        let func = make_func(vec![(
            0,
            LlilInstruction::SetReg {
                dest: LlilRegister::Concrete("rax".into()),
                size: Size::QWord,
                value: expr,
            },
        )]);
        interp.load_function(&func).unwrap();
        interp.step().unwrap();
        assert_eq!(interp.cpu.read_reg("rax"), 0x7F);
    }

    #[test]
    fn eval_cond_expr_true() {
        let mut interp = make_interp(8);
        let expr = LlilExpr::CondExpr {
            cond: Box::new(LlilExpr::Const {
                value: 1,
                size: Size::Byte,
            }),
            true_val: Box::new(LlilExpr::Const {
                value: 10,
                size: Size::QWord,
            }),
            false_val: Box::new(LlilExpr::Const {
                value: 20,
                size: Size::QWord,
            }),
            size: Size::QWord,
        };
        let func = make_func(vec![(
            0,
            LlilInstruction::SetReg {
                dest: LlilRegister::Concrete("rax".into()),
                size: Size::QWord,
                value: expr,
            },
        )]);
        interp.load_function(&func).unwrap();
        interp.step().unwrap();
        assert_eq!(interp.cpu.read_reg("rax"), 10);
    }

    #[test]
    fn eval_cond_expr_false() {
        let mut interp = make_interp(8);
        let expr = LlilExpr::CondExpr {
            cond: Box::new(LlilExpr::Const {
                value: 0,
                size: Size::Byte,
            }),
            true_val: Box::new(LlilExpr::Const {
                value: 10,
                size: Size::QWord,
            }),
            false_val: Box::new(LlilExpr::Const {
                value: 20,
                size: Size::QWord,
            }),
            size: Size::QWord,
        };
        let func = make_func(vec![(
            0,
            LlilInstruction::SetReg {
                dest: LlilRegister::Concrete("rax".into()),
                size: Size::QWord,
                value: expr,
            },
        )]);
        interp.load_function(&func).unwrap();
        interp.step().unwrap();
        assert_eq!(interp.cpu.read_reg("rax"), 20);
    }

    #[test]
    fn eval_rotate_left() {
        let mut interp = make_interp(8);
        // 0x01 rotated left by 1 in a byte → 0x02
        let expr = LlilExpr::Rol(
            Box::new(LlilExpr::Const {
                value: 0x01,
                size: Size::Byte,
            }),
            Box::new(LlilExpr::Const {
                value: 1,
                size: Size::Byte,
            }),
            Size::Byte,
        );
        let func = make_func(vec![(
            0,
            LlilInstruction::SetReg {
                dest: LlilRegister::Concrete("al".into()),
                size: Size::Byte,
                value: expr,
            },
        )]);
        interp.load_function(&func).unwrap();
        interp.step().unwrap();
        assert_eq!(interp.cpu.read_reg_aliased("al"), 0x02);
    }

    #[test]
    fn eval_arithmetic_shift_right() {
        let mut interp = make_interp(8);
        // -4 (0xFFFF_FFFF_FFFF_FFFC) >> 1 should give -2 signed
        let expr = LlilExpr::Sar(
            Box::new(LlilExpr::Const {
                value: (-4i64 as u64),
                size: Size::QWord,
            }),
            Box::new(LlilExpr::Const {
                value: 1,
                size: Size::QWord,
            }),
            Size::QWord,
        );
        let func = make_func(vec![(
            0,
            LlilInstruction::SetReg {
                dest: LlilRegister::Concrete("rax".into()),
                size: Size::QWord,
                value: expr,
            },
        )]);
        interp.load_function(&func).unwrap();
        interp.step().unwrap();
        assert_eq!(interp.cpu.read_reg("rax") as i64, -2);
    }

    #[test]
    fn eval_sar_sign_extends_from_operand_width() {
        // SAR of a 32-bit negative: 0x8000_0000 as i32 is negative, so
        // `sar eax, 4` must bring in ones → 0xF800_0000, NOT 0x0800_0000.
        // The interpreter used to cast the raw u64 (0x0000_0000_8000_0000)
        // straight to i64 — a POSITIVE value — so it shifted in zeros.
        let mut interp = make_interp(8);
        let expr = LlilExpr::Sar(
            Box::new(LlilExpr::Const { value: 0x8000_0000, size: Size::DWord }),
            Box::new(LlilExpr::Const { value: 4, size: Size::DWord }),
            Size::DWord,
        );
        let func = make_func(vec![(
            0,
            LlilInstruction::SetReg {
                dest: LlilRegister::Concrete("eax".into()),
                size: Size::DWord,
                value: expr,
            },
        )]);
        interp.load_function(&func).unwrap();
        interp.step().unwrap();
        assert_eq!(interp.cpu.read_reg_aliased("eax"), 0xF800_0000);
    }

    #[test]
    fn exec_stats_memory() {
        let mut interp = make_interp(8);
        interp.mem.map(0x1000, &[0u8; 8]);
        let store = LlilInstruction::Store {
            addr: LlilExpr::Const {
                value: 0x1000,
                size: Size::QWord,
            },
            size: Size::DWord,
            value: LlilExpr::Const {
                value: 99,
                size: Size::DWord,
            },
        };
        let func = make_func(vec![(0, store)]);
        interp.load_function(&func).unwrap();
        interp.step().unwrap();
        assert_eq!(interp.stats.memory_writes, 1);
    }

    #[test]
    fn exec_undefined_expr_errors() {
        let mut interp = make_interp(8);
        let func = make_func(vec![(
            0,
            LlilInstruction::SetReg {
                dest: LlilRegister::Concrete("rax".into()),
                size: Size::QWord,
                value: LlilExpr::Undefined(Size::QWord),
            },
        )]);
        interp.load_function(&func).unwrap();
        assert!(matches!(interp.step(), Err(InterpError::UndefinedValue)));
    }

    #[test]
    fn null_interceptor_errors_on_syscall() {
        let mut interp = make_interp(8);
        let func = make_func(vec![(0, LlilInstruction::SysCall)]);
        interp.load_function(&func).unwrap();
        assert!(matches!(
            interp.step(),
            Err(InterpError::UnhandledSyscall(_))
        ));
    }

    #[test]
    fn exec_breakpoint_continues() {
        let mut interp = make_interp(8);
        let func = make_func(vec![(0, LlilInstruction::Breakpoint)]);
        interp.load_function(&func).unwrap();
        assert_eq!(interp.step().unwrap(), StepResult::Continue);
    }

    #[test]
    fn exec_xor_self_is_zero() {
        let mut interp = make_interp(8);
        interp.cpu.write_reg("rax", 0xABC);
        let src = LlilExpr::Xor(
            Box::new(LlilExpr::RegisterRef {
                reg: LlilRegister::Concrete("rax".into()),
                size: Size::QWord,
            }),
            Box::new(LlilExpr::RegisterRef {
                reg: LlilRegister::Concrete("rax".into()),
                size: Size::QWord,
            }),
            Size::QWord,
        );
        let func = make_func(vec![(
            0,
            LlilInstruction::SetReg {
                dest: LlilRegister::Concrete("rax".into()),
                size: Size::QWord,
                value: src,
            },
        )]);
        interp.load_function(&func).unwrap();
        interp.step().unwrap();
        assert_eq!(interp.cpu.read_reg("rax"), 0);
    }

    #[test]
    fn exec_signed_div() {
        let mut interp = make_interp(8);
        let src = LlilExpr::DivS(
            Box::new(LlilExpr::Const {
                value: (-10i64) as u64,
                size: Size::QWord,
            }),
            Box::new(LlilExpr::Const {
                value: 2,
                size: Size::QWord,
            }),
            Size::QWord,
        );
        let func = make_func(vec![(
            0,
            LlilInstruction::SetReg {
                dest: LlilRegister::Concrete("rax".into()),
                size: Size::QWord,
                value: src,
            },
        )]);
        interp.load_function(&func).unwrap();
        interp.step().unwrap();
        assert_eq!(interp.cpu.read_reg("rax") as i64, -5);
    }

    #[test]
    fn exec_low_part() {
        let mut interp = make_interp(8);
        let src = LlilExpr::LowPart {
            expr: Box::new(LlilExpr::Const {
                value: 0xDEAD_BEEF_CAFE,
                size: Size::QWord,
            }),
            to: Size::Word,
        };
        let func = make_func(vec![(
            0,
            LlilInstruction::SetReg {
                dest: LlilRegister::Concrete("ax".into()),
                size: Size::Word,
                value: src,
            },
        )]);
        interp.load_function(&func).unwrap();
        interp.step().unwrap();
        assert_eq!(interp.cpu.read_reg_aliased("ax"), 0xCAFE);
    }

    // --- ExecutionTrace tests ---

    #[test]
    fn trace_record_and_visited() {
        let mut t = ExecutionTrace::new(10);
        t.record(0x100);
        assert!(t.visited(0x100));
        assert!(!t.visited(0x200));
    }

    #[test]
    fn trace_capacity_drops_oldest() {
        let mut t = ExecutionTrace::new(2);
        t.record(1);
        t.record(2);
        t.record(3);
        assert!(!t.visited(1));
        assert!(t.visited(2));
        assert!(t.visited(3));
    }

    #[test]
    fn trace_clear() {
        let mut t = ExecutionTrace::new(10);
        t.record(0x100);
        t.clear();
        assert!(t.addresses().is_empty());
    }

    // --- MemoryRegion tests ---

    #[test]
    fn memory_region_contains() {
        let r = MemoryRegion::new(0x1000, 0x1000, "text", false);
        assert!(r.contains(0x1000));
        assert!(r.contains(0x1FFF));
        assert!(!r.contains(0x2000));
    }

    #[test]
    fn memory_region_end() {
        let r = MemoryRegion::new(0x1000, 0x200, "stack", true);
        assert_eq!(r.end(), 0x1200);
    }

    // --- MemoryMap tests ---

    #[test]
    fn memory_map_region_at() {
        let mut m = MemoryMap::default();
        m.add(MemoryRegion::new(0x1000, 0x1000, "text", false));
        assert!(m.region_at(0x1500).is_some());
        assert!(m.region_at(0x3000).is_none());
    }

    #[test]
    fn memory_map_apply_to() {
        let mut m = MemoryMap::default();
        m.add(MemoryRegion::new(0x1000, 16, "data", true));
        let mut mem = MemoryState::new();
        m.apply_to(&mut mem);
        assert_eq!(mem.read(0x1000, Size::Byte).unwrap(), 0);
    }

    // --- RegisterSnapshot tests ---

    #[test]
    fn register_snapshot_of() {
        let mut cpu = CpuState::new(8);
        cpu.write_reg("rax", 42);
        cpu.pc = 0x100;
        let snap = RegisterSnapshot::of(&cpu);
        assert_eq!(snap.registers["rax"], 42);
        assert_eq!(snap.pc, 0x100);
    }

    #[test]
    fn register_snapshot_diff() {
        let mut cpu = CpuState::new(8);
        cpu.write_reg("rax", 10);
        let snap1 = RegisterSnapshot::of(&cpu);
        cpu.write_reg("rax", 20);
        let snap2 = RegisterSnapshot::of(&cpu);
        let diffs = snap1.diff(&snap2);
        assert!(diffs.contains(&"rax"));
    }

    // --- WatchPoint tests ---

    #[test]
    fn watchpoint_read_write() {
        let w = WatchPoint::read_write(0xDEAD);
        assert!(w.on_read);
        assert!(w.on_write);
    }

    #[test]
    fn watchpoint_write_only() {
        let w = WatchPoint::write_only(0xDEAD);
        assert!(!w.on_read);
        assert!(w.on_write);
    }

    // --- InterpreterBuilder tests ---

    #[test]
    fn builder_x64_creates() {
        let interp = InterpreterBuilder::x64().build();
        assert_eq!(interp.cpu.ptr_size, 8);
    }

    #[test]
    fn builder_x86_creates() {
        let interp = InterpreterBuilder::x86().build();
        assert_eq!(interp.cpu.ptr_size, 4);
    }

    #[test]
    fn builder_custom_step_limit() {
        let interp = InterpreterBuilder::x64().step_limit(50).build();
        assert_eq!(interp.step_limit, 50);
    }

    #[test]
    fn builder_lenient_reads_zero() {
        let interp = InterpreterBuilder::x64().lenient().build();
        assert_eq!(interp.mem.read(0xDEAD_BEEF, Size::Byte).unwrap(), 0);
    }

    #[test]
    fn interp_error_converges_to_il_error() {
        let e: rustre_il::IlError =
            InterpError::UnsupportedInstruction("cpuid".to_string()).into();
        assert_eq!(e.to_string(), "unsupported operation `cpuid` at tier llil");

        // A runtime fault is not "unsupported" — it degrades to Invalid with
        // the original message intact.
        let e: rustre_il::IlError = InterpError::DivisionByZero.into();
        assert_eq!(e.to_string(), "invalid IL: division by zero");
    }
}
