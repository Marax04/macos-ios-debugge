//! `rustre-emu` — Base emulation framework.
//!
//! Provides the core abstraction layer for instruction emulators: traits, types,
//! a pure-Rust fallback interpreter for x86, high-level session API, and tooling
//! for coverage collection, MMIO, I/O ports, interrupts, and snapshots.
//!
//! # Sub-modules
//!
//! * [`arm_interpreter`] — Pure-Rust ARM Thumb / Thumb-2 interpreter.
//! * [`mips_interpreter`] — Pure-Rust MIPS32 (big- and little-endian) interpreter.
//! * [`os_emulation`] — Linux x86-64 + Windows x86-64 syscall emulation layer.
//! * [`fuzzing_integration`] — AFL-style coverage bitmap, corpus management,
//!   snapshot-reset fuzz loop, and coverage-guided random mutator.
//! * [`taint_emulation`] — Taint-tracking wrapper for any `Emulator` impl.

pub mod arm_interpreter;
pub mod fuzzing_integration;
pub mod heap_emulator;
pub mod jit_compiler;
pub mod library_stub;
pub mod mips_interpreter;
pub mod os_emulation;
pub mod os_syscall_model;
pub mod structured_execution;
pub mod syscall_emulation;
pub mod taint_emulation;
pub mod emu_device_model;
pub mod emu_interrupt_controller;
pub mod emu_execution_statistics;
pub mod backends_registry;
pub mod mem_provider;

pub use mem_provider::{
    EmuCompositeMemoryProvider, EmuMemoryProvider, EmuVirtualMemoryProvider,
};

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};

use bitflags::bitflags;
use serde::{Deserialize, Serialize};
use thiserror::Error;

// ── Architecture ─────────────────────────────────────────────────────────────

/// CPU architecture supported by the emulation layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EmulatorArch {
    X86_16,
    X86_32,
    X86_64,
    Arm,
    ArmThumb,
    Arm64,
    Mips32,
    Mips64,
    Mips32El,
    RiscV32,
    RiscV64,
    Sparc32,
    Sparc64,
}

impl EmulatorArch {
    #[must_use]
    pub const fn pointer_size(self) -> usize {
        match self {
            Self::X86_16 => 2,
            Self::X86_32
            | Self::Arm
            | Self::ArmThumb
            | Self::Mips32
            | Self::Mips32El
            | Self::RiscV32
            | Self::Sparc32 => 4,
            Self::X86_64 | Self::Arm64 | Self::Mips64 | Self::RiscV64 | Self::Sparc64 => 8,
        }
    }
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::X86_16 => "x86-16",
            Self::X86_32 => "x86-32",
            Self::X86_64 => "x86-64",
            Self::Arm => "arm",
            Self::ArmThumb => "arm-thumb",
            Self::Arm64 => "arm64",
            Self::Mips32 => "mips32",
            Self::Mips64 => "mips64",
            Self::Mips32El => "mips32el",
            Self::RiscV32 => "riscv32",
            Self::RiscV64 => "riscv64",
            Self::Sparc32 => "sparc32",
            Self::Sparc64 => "sparc64",
        }
    }
    #[must_use]
    pub const fn is_64bit(self) -> bool {
        self.pointer_size() == 8
    }
    #[must_use]
    pub const fn is_x86(self) -> bool {
        matches!(self, Self::X86_16 | Self::X86_32 | Self::X86_64)
    }
}

// ── Memory permissions ────────────────────────────────────────────────────────

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
    pub struct MemPerms: u32 {
        const NONE  = 0;
        const READ  = 1;
        const WRITE = 2;
        const EXEC  = 4;
        const ALL   = Self::READ.bits() | Self::WRITE.bits() | Self::EXEC.bits();
    }
}

impl MemPerms {
    /// Short alias for `READ`.
    pub const R: Self = Self::READ;
    /// Short alias for `WRITE`.
    pub const W: Self = Self::WRITE;
    /// Short alias for `EXEC`.
    pub const X: Self = Self::EXEC;
    /// Read + Write.
    pub const RW: Self = Self::READ.union(Self::WRITE);
    /// Read + Execute.
    pub const RX: Self = Self::READ.union(Self::EXEC);
    /// Read + Write + Execute (alias of `ALL`).
    pub const RWX: Self = Self::ALL;
}

// ── Memory region ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemRegion {
    pub start: u64,
    pub size: usize,
    pub perms: MemPerms,
    pub label: Option<String>,
}

impl MemRegion {
    #[must_use]
    pub const fn new(start: u64, size: usize, perms: MemPerms) -> Self {
        Self {
            start,
            size,
            perms,
            label: None,
        }
    }
    #[must_use]
    pub fn with_label(mut self, label: impl Into<String>) -> Self {
        self.label = Some(label.into());
        self
    }
    #[must_use]
    pub const fn end(&self) -> u64 {
        self.start + self.size as u64
    }
    #[must_use]
    pub const fn contains(&self, addr: u64) -> bool {
        addr >= self.start && addr < self.end()
    }
}

// ── Errors ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum EmulatorError {
    #[error("memory fault at 0x{addr:016x} ({op})")]
    MemFault { addr: u64, op: String },
    #[error("invalid instruction at 0x{addr:016x}")]
    InvalidInsn { addr: u64 },
    #[error("emulation timeout")]
    Timeout,
    #[error("hook error: {0}")]
    HookError(String),
    #[error("invalid argument: {0}")]
    InvalidArg(String),
    #[error("init error: {0}")]
    InitError(String),
    #[error("unsupported operation")]
    Unsupported,
}

// ── Hook types ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum HookKind {
    Code,
    MemRead,
    MemWrite,
    MemFetch,
    MemUnmapped,
    Interrupt,
    InsnInvalid,
    /// Legacy alias kept for compat.
    MemInvalid,
    /// Specific instruction opcode.
    Insn(u32),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct HookHandle(pub u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SnapshotId(pub u64);

// ── Emulator trait ────────────────────────────────────────────────────────────

/// Core abstraction for a CPU emulator.
pub trait Emulator: Send + Sync {
    fn arch(&self) -> EmulatorArch;
    /// # Errors
    /// Returns `EmulatorError` if mapping the memory region fails.
    fn map_memory(&mut self, addr: u64, size: usize, perms: MemPerms) -> Result<(), EmulatorError>;
    /// # Errors
    /// Returns `EmulatorError` if unmapping the memory region fails.
    fn unmap_memory(&mut self, addr: u64) -> Result<(), EmulatorError>;
    /// # Errors
    /// Returns `EmulatorError` if writing memory fails (e.g. permission or fault).
    fn write_memory(&mut self, addr: u64, data: &[u8]) -> Result<(), EmulatorError>;
    /// # Errors
    /// Returns `EmulatorError` if reading memory fails (e.g. permission or fault).
    fn read_memory(&self, addr: u64, len: usize) -> Result<Vec<u8>, EmulatorError>;
    /// # Errors
    /// Returns `EmulatorError::InvalidArg` if `reg` is not a valid register.
    fn read_register(&self, reg: u32) -> Result<u64, EmulatorError>;
    /// # Errors
    /// Returns `EmulatorError::InvalidArg` if `reg` is not a valid register.
    fn write_register(&mut self, reg: u32, value: u64) -> Result<(), EmulatorError>;
    /// # Errors
    /// Returns `EmulatorError::Timeout` if `timeout_ms` is exceeded, or other emulator faults.
    fn start(
        &mut self,
        begin: u64,
        until: u64,
        timeout_ms: u64,
        count: u64,
    ) -> Result<(), EmulatorError>;
    /// # Errors
    /// Returns `EmulatorError` if the emulator cannot signal stop.
    fn stop(&mut self) -> Result<(), EmulatorError>;
    /// # Errors
    /// Returns `EmulatorError` if installing the hook fails.
    fn add_code_hook(
        &mut self,
        begin: u64,
        end: u64,
        callback: Box<dyn Fn(u64, u32) + Send + Sync>,
    ) -> Result<HookHandle, EmulatorError>;
    /// # Errors
    /// Returns `EmulatorError` if installing the hook fails.
    fn add_mem_hook(
        &mut self,
        kind: HookKind,
        callback: Box<dyn Fn(u64, usize, u64) + Send + Sync>,
    ) -> Result<HookHandle, EmulatorError>;
    /// # Errors
    /// Returns `EmulatorError` if `handle` is unknown or removal fails.
    fn remove_hook(&mut self, handle: HookHandle) -> Result<(), EmulatorError>;
    /// # Errors
    /// Returns `EmulatorError` if serialization of the context fails.
    fn context_save(&self) -> Result<Vec<u8>, EmulatorError>;
    /// # Errors
    /// Returns `EmulatorError` if `ctx` is malformed or restoration fails.
    fn context_restore(&mut self, ctx: &[u8]) -> Result<(), EmulatorError>;
    fn regions(&self) -> Vec<MemRegion>;
}

// ── EmulatorBackend trait ─────────────────────────────────────────────────────

/// Factory trait for emulator back-ends (Unicorn, Qiling, etc.).
pub trait EmulatorBackend: Send + Sync {
    fn name(&self) -> &str;
    fn supported_arches(&self) -> Vec<EmulatorArch>;
    fn create(&self, arch: EmulatorArch) -> Box<dyn Emulator>;
    fn is_available(&self) -> bool {
        true
    }
}

// ── EmulatorRegistry ──────────────────────────────────────────────────────────

/// Registry of named emulator back-ends.
pub struct EmulatorRegistry {
    backends: HashMap<String, Box<dyn EmulatorBackend>>,
}

impl EmulatorRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self {
            backends: HashMap::new(),
        }
    }
    pub fn register(&mut self, backend: Box<dyn EmulatorBackend>) {
        self.backends.insert(backend.name().to_string(), backend);
    }
    /// Create an emulator for `arch`, auto-selecting the best available back-end.
    #[must_use]
    pub fn create(&self, arch: EmulatorArch) -> Option<Box<dyn Emulator>> {
        // Prefer back-ends that support the requested arch, sorted by name for determinism.
        let mut names: Vec<&str> = self
            .backends
            .keys()
            .map(std::string::String::as_str)
            .collect();
        names.sort_unstable();
        for name in names {
            let b = &self.backends[name];
            if b.is_available() && b.supported_arches().contains(&arch) {
                return Some(b.create(arch));
            }
        }
        None
    }
    #[must_use]
    pub fn names(&self) -> Vec<&str> {
        self.backends
            .keys()
            .map(std::string::String::as_str)
            .collect()
    }
}

impl Default for EmulatorRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ── Register ID constants ─────────────────────────────────────────────────────

pub mod x86_regs {
    pub const EAX: u32 = 0;
    pub const ECX: u32 = 1;
    pub const EDX: u32 = 2;
    pub const EBX: u32 = 3;
    pub const ESP: u32 = 4;
    pub const EBP: u32 = 5;
    pub const ESI: u32 = 6;
    pub const EDI: u32 = 7;
    pub const EIP: u32 = 8;
    pub const EFLAGS: u32 = 9;
    pub const RAX: u32 = 10;
    pub const RCX: u32 = 11;
    pub const RDX: u32 = 12;
    pub const RBX: u32 = 13;
    pub const RSP: u32 = 14;
    pub const RBP: u32 = 15;
    pub const RSI: u32 = 16;
    pub const RDI: u32 = 17;
    pub const RIP: u32 = 18;
    pub const RFLAGS: u32 = 19;
    pub const R8: u32 = 20;
    pub const R9: u32 = 21;
    pub const R10: u32 = 22;
    pub const R11: u32 = 23;
    pub const R12: u32 = 24;
    pub const R13: u32 = 25;
    pub const R14: u32 = 26;
    pub const R15: u32 = 27;
}

pub mod arm_regs {
    pub const R0: u32 = 0;
    pub const R1: u32 = 1;
    pub const R2: u32 = 2;
    pub const R3: u32 = 3;
    pub const R4: u32 = 4;
    pub const R5: u32 = 5;
    pub const R6: u32 = 6;
    pub const R7: u32 = 7;
    pub const R8: u32 = 8;
    pub const R9: u32 = 9;
    pub const R10: u32 = 10;
    pub const R11: u32 = 11;
    pub const R12: u32 = 12;
    pub const SP: u32 = 13;
    pub const LR: u32 = 14;
    pub const PC: u32 = 15;
    pub const CPSR: u32 = 16;
}

pub mod arm64_regs {
    pub const X0: u32 = 0;
    pub const X1: u32 = 1;
    pub const X2: u32 = 2;
    pub const X3: u32 = 3;
    pub const X4: u32 = 4;
    pub const X5: u32 = 5;
    pub const X6: u32 = 6;
    pub const X7: u32 = 7;
    pub const X8: u32 = 8;
    pub const X9: u32 = 9;
    pub const X10: u32 = 10;
    pub const X11: u32 = 11;
    pub const X12: u32 = 12;
    pub const X13: u32 = 13;
    pub const X14: u32 = 14;
    pub const X15: u32 = 15;
    pub const X16: u32 = 16;
    pub const X17: u32 = 17;
    pub const X18: u32 = 18;
    pub const X19: u32 = 19;
    pub const X20: u32 = 20;
    pub const X21: u32 = 21;
    pub const X22: u32 = 22;
    pub const X23: u32 = 23;
    pub const X24: u32 = 24;
    pub const X25: u32 = 25;
    pub const X26: u32 = 26;
    pub const X27: u32 = 27;
    pub const X28: u32 = 28;
    pub const X29: u32 = 29;
    pub const X30: u32 = 30;
    pub const SP: u32 = 31;
    pub const PC: u32 = 32;
    pub const NZCV: u32 = 33;
}

pub mod mips_regs {
    pub const ZERO: u32 = 0;
    pub const AT: u32 = 1;
    pub const V0: u32 = 2;
    pub const V1: u32 = 3;
    pub const A0: u32 = 4;
    pub const A1: u32 = 5;
    pub const A2: u32 = 6;
    pub const A3: u32 = 7;
    pub const T0: u32 = 8;
    pub const T1: u32 = 9;
    pub const T2: u32 = 10;
    pub const T3: u32 = 11;
    pub const T4: u32 = 12;
    pub const T5: u32 = 13;
    pub const T6: u32 = 14;
    pub const T7: u32 = 15;
    pub const S0: u32 = 16;
    pub const S1: u32 = 17;
    pub const S2: u32 = 18;
    pub const S3: u32 = 19;
    pub const S4: u32 = 20;
    pub const S5: u32 = 21;
    pub const S6: u32 = 22;
    pub const S7: u32 = 23;
    pub const T8: u32 = 24;
    pub const T9: u32 = 25;
    pub const K0: u32 = 26;
    pub const K1: u32 = 27;
    pub const GP: u32 = 28;
    pub const SP: u32 = 29;
    pub const FP: u32 = 30;
    pub const RA: u32 = 31;
    pub const PC: u32 = 32;
    pub const HI: u32 = 33;
    pub const LO: u32 = 34;
}

pub mod riscv_regs {
    pub const ZERO: u32 = 0;
    pub const RA: u32 = 1;
    pub const SP: u32 = 2;
    pub const GP: u32 = 3;
    pub const TP: u32 = 4;
    pub const T0: u32 = 5;
    pub const T1: u32 = 6;
    pub const T2: u32 = 7;
    pub const S0: u32 = 8;
    pub const S1: u32 = 9;
    pub const A0: u32 = 10;
    pub const A1: u32 = 11;
    pub const A2: u32 = 12;
    pub const A3: u32 = 13;
    pub const A4: u32 = 14;
    pub const A5: u32 = 15;
    pub const A6: u32 = 16;
    pub const A7: u32 = 17;
    pub const S2: u32 = 18;
    pub const S3: u32 = 19;
    pub const S4: u32 = 20;
    pub const S5: u32 = 21;
    pub const S6: u32 = 22;
    pub const S7: u32 = 23;
    pub const S8: u32 = 24;
    pub const S9: u32 = 25;
    pub const S10: u32 = 26;
    pub const S11: u32 = 27;
    pub const T3: u32 = 28;
    pub const T4: u32 = 29;
    pub const T5: u32 = 30;
    pub const T6: u32 = 31;
    pub const PC: u32 = 32;
}

// ── CPU state ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CpuState {
    pub regs: HashMap<u32, u64>,
    pub flags: u64,
    pub memory: BTreeMap<u64, Vec<u8>>,
}

impl CpuState {
    fn new_x86_64() -> Self {
        let mut s = Self {
            regs: HashMap::with_capacity(28),
            ..Self::default()
        };
        for &r in &[
            x86_regs::EAX,
            x86_regs::ECX,
            x86_regs::EDX,
            x86_regs::EBX,
            x86_regs::ESP,
            x86_regs::EBP,
            x86_regs::ESI,
            x86_regs::EDI,
            x86_regs::EIP,
            x86_regs::EFLAGS,
            x86_regs::RAX,
            x86_regs::RCX,
            x86_regs::RDX,
            x86_regs::RBX,
            x86_regs::RSP,
            x86_regs::RBP,
            x86_regs::RSI,
            x86_regs::RDI,
            x86_regs::RIP,
            x86_regs::RFLAGS,
            x86_regs::R8,
            x86_regs::R9,
            x86_regs::R10,
            x86_regs::R11,
            x86_regs::R12,
            x86_regs::R13,
            x86_regs::R14,
            x86_regs::R15,
        ] {
            s.regs.insert(r, 0);
        }
        s
    }
}

// ── Memory helpers ────────────────────────────────────────────────────────────

fn mem_read(
    memory: &BTreeMap<u64, Vec<u8>>,
    regions: &[MemRegion],
    addr: u64,
    len: usize,
) -> Result<Vec<u8>, EmulatorError> {
    let region =
        regions
            .iter()
            .find(|r| r.contains(addr))
            .ok_or_else(|| EmulatorError::MemFault {
                addr,
                op: "read".into(),
            })?;
    if !region.perms.contains(MemPerms::READ) {
        return Err(EmulatorError::MemFault {
            addr,
            op: "read".into(),
        });
    }
    let base = region.start;
    let buf = memory.get(&base).ok_or_else(|| EmulatorError::MemFault {
        addr,
        op: "read".into(),
    })?;
    let offset = usize::try_from(addr - base).unwrap_or(usize::MAX);
    if offset + len > buf.len() {
        return Err(EmulatorError::MemFault {
            addr: addr + (buf.len().saturating_sub(offset)) as u64,
            op: "read-oob".into(),
        });
    }
    Ok(buf[offset..offset + len].to_vec())
}

fn mem_write(
    memory: &mut BTreeMap<u64, Vec<u8>>,
    regions: &[MemRegion],
    addr: u64,
    data: &[u8],
) -> Result<(), EmulatorError> {
    let region =
        regions
            .iter()
            .find(|r| r.contains(addr))
            .ok_or_else(|| EmulatorError::MemFault {
                addr,
                op: "write".into(),
            })?;
    if !region.perms.contains(MemPerms::WRITE) {
        return Err(EmulatorError::MemFault {
            addr,
            op: "write".into(),
        });
    }
    let base = region.start;
    let buf = memory
        .get_mut(&base)
        .ok_or_else(|| EmulatorError::MemFault {
            addr,
            op: "write".into(),
        })?;
    let offset = usize::try_from(addr - base).unwrap_or(usize::MAX);
    if offset + data.len() > buf.len() {
        return Err(EmulatorError::MemFault {
            addr: addr + (buf.len().saturating_sub(offset)) as u64,
            op: "write-oob".into(),
        });
    }
    buf[offset..offset + data.len()].copy_from_slice(data);
    Ok(())
}

// ── SimpleInterpreter ─────────────────────────────────────────────────────────

type CodeHook = (u64, u64, Box<dyn Fn(u64, u32) + Send + Sync>);
type MemHook = (HookKind, Box<dyn Fn(u64, usize, u64) + Send + Sync>);

/// Minimal pure-Rust x86 interpreter (NOP/MOV/ADD/SUB/PUSH/POP/CALL/RET/JMP/Jcc/INT).
pub struct SimpleInterpreter {
    arch: EmulatorArch,
    state: CpuState,
    regions: Vec<MemRegion>,
    hook_counter: u64,
    code_hooks: Vec<(HookHandle, CodeHook)>,
    mem_hooks: Vec<(HookHandle, MemHook)>,
    stop_requested: bool,
}

impl SimpleInterpreter {
    #[must_use]
    pub fn new(arch: EmulatorArch) -> Self {
        let state = match arch {
            EmulatorArch::X86_64 | EmulatorArch::X86_32 | EmulatorArch::X86_16 => {
                CpuState::new_x86_64()
            }
            _ => CpuState::default(),
        };
        Self {
            arch,
            state,
            regions: Vec::new(),
            hook_counter: 0,
            code_hooks: Vec::new(),
            mem_hooks: Vec::new(),
            stop_requested: false,
        }
    }

    const fn next_handle(&mut self) -> HookHandle {
        self.hook_counter += 1;
        HookHandle(self.hook_counter)
    }

    fn rip(&self) -> u64 {
        match self.arch {
            EmulatorArch::X86_64 => *self.state.regs.get(&x86_regs::RIP).unwrap_or(&0),
            _ => *self.state.regs.get(&x86_regs::EIP).unwrap_or(&0),
        }
    }

    fn set_rip(&mut self, v: u64) {
        match self.arch {
            EmulatorArch::X86_64 => {
                self.state.regs.insert(x86_regs::RIP, v);
            }
            _ => {
                self.state.regs.insert(x86_regs::EIP, v & 0xFFFF_FFFF);
            }
        }
    }

    fn sp(&self) -> u64 {
        match self.arch {
            EmulatorArch::X86_64 => *self.state.regs.get(&x86_regs::RSP).unwrap_or(&0),
            _ => *self.state.regs.get(&x86_regs::ESP).unwrap_or(&0),
        }
    }

    fn set_sp(&mut self, v: u64) {
        match self.arch {
            EmulatorArch::X86_64 => {
                self.state.regs.insert(x86_regs::RSP, v);
            }
            _ => {
                self.state.regs.insert(x86_regs::ESP, v & 0xFFFF_FFFF);
            }
        }
    }

    fn push_value(&mut self, val: u64) -> Result<(), EmulatorError> {
        let ptrsize = self.arch.pointer_size() as u64;
        let new_sp = self.sp().wrapping_sub(ptrsize);
        self.set_sp(new_sp);
        let bytes = match ptrsize {
            8 => val.to_le_bytes().to_vec(),
            4 => u32::try_from(val & 0xFFFF_FFFF)
                .unwrap_or(0_u32)
                .to_le_bytes()
                .to_vec(),
            2 => u16::try_from(val & 0xFFFF)
                .unwrap_or(0_u16)
                .to_le_bytes()
                .to_vec(),
            _ => return Err(EmulatorError::Unsupported),
        };
        self.fire_mem_hooks(&HookKind::MemWrite, new_sp, bytes.len(), val);
        mem_write(&mut self.state.memory, &self.regions, new_sp, &bytes)
    }

    fn pop_value(&mut self) -> Result<u64, EmulatorError> {
        let ptrsize = self.arch.pointer_size();
        let sp = self.sp();
        self.fire_mem_hooks(&HookKind::MemRead, sp, ptrsize, 0);
        let bytes = mem_read(&self.state.memory, &self.regions, sp, ptrsize)?;
        self.set_sp(sp.wrapping_add(ptrsize as u64));
        Ok(match ptrsize {
            8 => u64::from_le_bytes(bytes.try_into().unwrap_or([0u8; 8])),
            4 => u64::from(u32::from_le_bytes(bytes.try_into().unwrap_or([0u8; 4]))),
            2 => u64::from(u16::from_le_bytes(bytes.try_into().unwrap_or([0u8; 2]))),
            _ => return Err(EmulatorError::Unsupported),
        })
    }

    fn fire_code_hooks(&self, pc: u64, insn_size: u32) {
        for (_, (begin, end, cb)) in &self.code_hooks {
            if pc >= *begin && pc < *end {
                cb(pc, insn_size);
            }
        }
    }

    fn fire_mem_hooks(&self, kind: &HookKind, addr: u64, size: usize, val: u64) {
        for (_, (hkind, cb)) in &self.mem_hooks {
            if hkind == kind {
                cb(addr, size, val);
            }
        }
    }

    fn step_x86_arith(&mut self, b0: u8, raw: &[u8], pc: u64) -> (u32, Option<u64>) {
        let imm = u64::from(u32::from_le_bytes([raw[1], raw[2], raw[3], raw[4]]));
        let reg = if self.arch == EmulatorArch::X86_64 {
            x86_regs::RAX
        } else {
            x86_regs::EAX
        };
        let old = *self.state.regs.get(&reg).unwrap_or(&0);
        match b0 {
            0x05 => {
                self.state.regs.insert(reg, old.wrapping_add(imm));
            }
            0x2D => {
                self.state.regs.insert(reg, old.wrapping_sub(imm));
            }
            0x35 => {
                self.state.regs.insert(reg, old ^ imm);
            }
            _ => {
                self.state.regs.insert(reg, imm);
            }
        }
        (5, Some(pc + 5))
    }

    fn step_x86_cmp(&mut self, b0: u8, raw: &[u8], pc: u64) -> (u32, Option<u64>) {
        let reg = if self.arch == EmulatorArch::X86_64 {
            x86_regs::RAX
        } else {
            x86_regs::EAX
        };
        if b0 == 0x3C {
            let al = *self.state.regs.get(&reg).unwrap_or(&0) & 0xFF;
            let imm = u64::from(raw[1]);
            if al == imm {
                self.state.flags |= 0x40;
            } else {
                self.state.flags &= !0x40;
            }
            (2, Some(pc + 2))
        } else {
            let eax = *self.state.regs.get(&reg).unwrap_or(&0) & 0xFFFF_FFFF;
            let imm = u64::from(u32::from_le_bytes([raw[1], raw[2], raw[3], raw[4]]));
            if eax == imm {
                self.state.flags |= 0x40;
            } else {
                self.state.flags &= !0x40;
            }
            (5, Some(pc + 5))
        }
    }

    fn step_x86_cf(
        &mut self,
        b0: u8,
        raw: &[u8],
        pc: u64,
        stop_on_ret: bool,
    ) -> Result<(u32, Option<u64>), EmulatorError> {
        match b0 {
            0xC3 => {
                if stop_on_ret {
                    return Ok((1, None));
                }
                let r = self.pop_value()?;
                Ok((1, Some(r)))
            }
            0xC2 => {
                let adj = u64::from(u16::from_le_bytes([raw[1], raw[2]]));
                if stop_on_ret {
                    let _ = self.pop_value();
                    let sp = self.sp();
                    self.set_sp(sp.wrapping_add(adj));
                    return Ok((3, None));
                }
                let r = self.pop_value()?;
                let sp = self.sp();
                self.set_sp(sp.wrapping_add(adj));
                Ok((3, Some(r)))
            }
            0xE8 => {
                let rel = i64::from(i32::from_le_bytes([raw[1], raw[2], raw[3], raw[4]]));
                let next = pc.wrapping_add(5);
                let target = next.wrapping_add_signed(rel);
                self.push_value(next)?;
                Ok((5, Some(target)))
            }
            0xEB => {
                let rel = i64::from(i8::from_ne_bytes([raw[1]]));
                Ok((2, Some(pc.wrapping_add(2).wrapping_add_signed(rel))))
            }
            0xE9 => {
                let rel = i64::from(i32::from_le_bytes([raw[1], raw[2], raw[3], raw[4]]));
                Ok((5, Some(pc.wrapping_add(5).wrapping_add_signed(rel))))
            }
            _ => {
                let cond = b0 & 0x0F;
                let rel = i64::from(i8::from_ne_bytes([raw[1]]));
                let taken = self.eval_condition_x86(cond);
                let target = if taken {
                    pc.wrapping_add(2).wrapping_add_signed(rel)
                } else {
                    pc + 2
                };
                Ok((2, Some(target)))
            }
        }
    }

    fn step_x86(&mut self, until: u64, stop_on_ret: bool) -> Result<Option<u64>, EmulatorError> {
        if self.stop_requested {
            return Ok(None);
        }
        let pc = self.rip();
        if pc == until {
            return Ok(None);
        }
        let raw = {
            let mut buf: Option<Vec<u8>> = None;
            for try_len in (1..=15).rev() {
                if let Ok(b) = mem_read(&self.state.memory, &self.regions, pc, try_len) {
                    buf = Some(b);
                    break;
                }
            }
            match buf {
                Some(mut b) => {
                    if b.len() < 15 {
                        b.resize(15, 0);
                    }
                    b
                }
                None => return Err(EmulatorError::InvalidInsn { addr: pc }),
            }
        };
        let b0 = raw[0];
        let (insn_size, new_pc): (u32, Option<u64>) = match b0 {
            0xCC => {
                self.fire_mem_hooks(&HookKind::Interrupt, pc, 1, 3);
                (1, Some(pc + 1))
            }
            0xF4 => (1, None),
            0x6A => {
                let imm = 0_u64.wrapping_add_signed(i64::from(i8::from_ne_bytes([raw[1]])));
                self.push_value(imm)?;
                (2, Some(pc + 2))
            }
            0x68 => {
                let imm = u64::from(u32::from_le_bytes([raw[1], raw[2], raw[3], raw[4]]));
                self.push_value(imm)?;
                (5, Some(pc + 5))
            }
            0x50..=0x57 => self.step_x86_push_reg(b0, pc)?,
            0x58..=0x5F => self.step_x86_pop_reg(b0, pc)?,
            0x05 | 0x2D | 0x35 | 0xB8 => self.step_x86_arith(b0, &raw, pc),
            0xB9..=0xBF => self.step_x86_mov_imm32(b0, &raw, pc),
            0xC2 | 0xC3 | 0xE8 | 0xE9 | 0xEB | 0x70..=0x7F => {
                self.step_x86_cf(b0, &raw, pc, stop_on_ret)?
            }
            0x0F => self.step_x86_two_byte(&raw, pc)?,
            0xC6 | 0x8D => (3, Some(pc + 3)),
            0xC7 => (6, Some(pc + 6)),
            0xCD => {
                let int_nr = u64::from(raw[1]);
                self.fire_mem_hooks(&HookKind::Interrupt, pc, 2, int_nr);
                (2, Some(pc + 2))
            }
            0x3C | 0x3D => self.step_x86_cmp(b0, &raw, pc),
            0x85 => (2, Some(pc + 2)),
            _ => (1, Some(pc + 1)),
        };
        self.fire_code_hooks(pc, insn_size);
        self.set_rip(new_pc.unwrap_or(pc));
        Ok(new_pc)
    }

    fn step_x86_push_reg(&mut self, b0: u8, pc: u64) -> Result<(u32, Option<u64>), EmulatorError> {
        let reg = u32::from(b0 - 0x50);
        let base = if self.arch == EmulatorArch::X86_64 { x86_regs::RAX } else { x86_regs::EAX };
        let val = *self.state.regs.get(&(base + reg)).unwrap_or(&0);
        self.push_value(val)?;
        Ok((1, Some(pc + 1)))
    }

    fn step_x86_pop_reg(&mut self, b0: u8, pc: u64) -> Result<(u32, Option<u64>), EmulatorError> {
        let reg = u32::from(b0 - 0x58);
        let base = if self.arch == EmulatorArch::X86_64 { x86_regs::RAX } else { x86_regs::EAX };
        let val = self.pop_value()?;
        self.state.regs.insert(base + reg, val);
        Ok((1, Some(pc + 1)))
    }

    fn step_x86_mov_imm32(&mut self, b0: u8, raw: &[u8], pc: u64) -> (u32, Option<u64>) {
        let reg_idx = u32::from(b0 - 0xB8);
        let imm = u64::from(u32::from_le_bytes([raw[1], raw[2], raw[3], raw[4]]));
        let base = if self.arch == EmulatorArch::X86_64 { x86_regs::RAX } else { x86_regs::EAX };
        self.state.regs.insert(base + reg_idx, imm);
        (5, Some(pc + 5))
    }

    fn step_x86_two_byte(&self, raw: &[u8], pc: u64) -> Result<(u32, Option<u64>), EmulatorError> {
        let b1 = raw[1];
        match b1 {
            0x80..=0x8F => {
                let cond = b1 & 0x0F;
                let rel = i64::from(i32::from_le_bytes([raw[2], raw[3], raw[4], raw[5]]));
                let taken = self.eval_condition_x86(cond);
                let target = if taken {
                    pc.wrapping_add(6).wrapping_add_signed(rel)
                } else {
                    pc + 6
                };
                Ok((6, Some(target)))
            }
            0x05 => {
                self.fire_mem_hooks(&HookKind::Interrupt, pc, 2, 0x100);
                Ok((2, Some(pc + 2)))
            }
            _ => Err(EmulatorError::InvalidInsn { addr: pc }),
        }
    }

    const fn eval_condition_x86(&self, cond: u8) -> bool {
        let zf = (self.state.flags & 0x40) != 0;
        let sf = (self.state.flags & 0x80) != 0;
        let of = (self.state.flags & 0x800) != 0;
        let cf = (self.state.flags & 0x01) != 0;
        match cond {
            0x0 => of,
            0x1 => !of,
            0x2 => cf,
            0x3 => !cf,
            0x4 => zf,
            0x5 => !zf,
            0x6 => cf || zf,
            0x7 => !cf && !zf,
            0x8 => sf,
            0x9 => !sf,
            0xB => true,
            0xC => sf != of,
            0xD => sf == of,
            0xE => zf || (sf != of),
            0xF => !zf && (sf == of),
            _ => false,
        }
    }
}

impl Emulator for SimpleInterpreter {
    fn arch(&self) -> EmulatorArch {
        self.arch
    }

    fn map_memory(&mut self, addr: u64, size: usize, perms: MemPerms) -> Result<(), EmulatorError> {
        if size == 0 {
            return Err(EmulatorError::InvalidArg("size must be > 0".into()));
        }
        for r in &self.regions {
            let r_end = r.start.saturating_add(r.size as u64);
            let end = addr.saturating_add(size as u64);
            if addr < r_end && end > r.start {
                return Err(EmulatorError::InvalidArg(format!(
                    "region 0x{addr:x}+{size} overlaps 0x{:x}+{}",
                    r.start, r.size
                )));
            }
        }
        self.regions.push(MemRegion::new(addr, size, perms));
        self.state.memory.insert(addr, vec![0u8; size]);
        Ok(())
    }

    fn unmap_memory(&mut self, addr: u64) -> Result<(), EmulatorError> {
        let pos = self
            .regions
            .iter()
            .position(|r| r.start == addr)
            .ok_or_else(|| EmulatorError::InvalidArg(format!("no region at 0x{addr:x}")))?;
        self.regions.remove(pos);
        self.state.memory.remove(&addr);
        Ok(())
    }

    fn write_memory(&mut self, addr: u64, data: &[u8]) -> Result<(), EmulatorError> {
        self.fire_mem_hooks(&HookKind::MemWrite, addr, data.len(), 0);
        mem_write(&mut self.state.memory, &self.regions, addr, data)
    }

    fn read_memory(&self, addr: u64, len: usize) -> Result<Vec<u8>, EmulatorError> {
        self.fire_mem_hooks(&HookKind::MemRead, addr, len, 0);
        mem_read(&self.state.memory, &self.regions, addr, len)
    }

    fn read_register(&self, reg: u32) -> Result<u64, EmulatorError> {
        self.state
            .regs
            .get(&reg)
            .copied()
            .ok_or_else(|| EmulatorError::InvalidArg(format!("unknown reg {reg}")))
    }

    fn write_register(&mut self, reg: u32, value: u64) -> Result<(), EmulatorError> {
        self.state.regs.insert(reg, value);
        Ok(())
    }

    fn start(
        &mut self,
        begin: u64,
        until: u64,
        timeout_ms: u64,
        count: u64,
    ) -> Result<(), EmulatorError> {
        self.stop_requested = false;
        self.set_rip(begin);
        let deadline = if timeout_ms > 0 {
            Some(std::time::Instant::now() + std::time::Duration::from_millis(timeout_ms))
        } else {
            None
        };
        let mut steps: u64 = 0;
        loop {
            if self.stop_requested {
                break;
            }
            if let Some(dl) = deadline
                && std::time::Instant::now() >= dl
            {
                return Err(EmulatorError::Timeout);
            }
            if count > 0 && steps >= count {
                break;
            }
            match self.step_x86(until, false)? {
                None => break,
                Some(new_pc) => {
                    if new_pc == until {
                        break;
                    }
                }
            }
            steps += 1;
        }
        Ok(())
    }

    fn stop(&mut self) -> Result<(), EmulatorError> {
        self.stop_requested = true;
        Ok(())
    }

    fn add_code_hook(
        &mut self,
        begin: u64,
        end: u64,
        callback: Box<dyn Fn(u64, u32) + Send + Sync>,
    ) -> Result<HookHandle, EmulatorError> {
        let h = self.next_handle();
        self.code_hooks.push((h, (begin, end, callback)));
        Ok(h)
    }

    fn add_mem_hook(
        &mut self,
        kind: HookKind,
        callback: Box<dyn Fn(u64, usize, u64) + Send + Sync>,
    ) -> Result<HookHandle, EmulatorError> {
        let h = self.next_handle();
        self.mem_hooks.push((h, (kind, callback)));
        Ok(h)
    }

    fn remove_hook(&mut self, handle: HookHandle) -> Result<(), EmulatorError> {
        let before = self.code_hooks.len() + self.mem_hooks.len();
        self.code_hooks.retain(|(h, _)| *h != handle);
        self.mem_hooks.retain(|(h, _)| *h != handle);
        let after = self.code_hooks.len() + self.mem_hooks.len();
        if before == after {
            Err(EmulatorError::HookError(format!(
                "hook {handle:?} not found"
            )))
        } else {
            Ok(())
        }
    }

    fn context_save(&self) -> Result<Vec<u8>, EmulatorError> {
        serde_json::to_vec(&self.state)
            .map_err(|e| EmulatorError::HookError(format!("serialize: {e}")))
    }

    fn context_restore(&mut self, ctx: &[u8]) -> Result<(), EmulatorError> {
        let state: CpuState = serde_json::from_slice(ctx)
            .map_err(|e| EmulatorError::HookError(format!("deserialize: {e}")))?;
        self.state = state;
        Ok(())
    }

    fn regions(&self) -> Vec<MemRegion> {
        self.regions.clone()
    }
}

// ── EmulatorFactory ───────────────────────────────────────────────────────────

pub struct EmulatorFactory;
impl EmulatorFactory {
    #[must_use]
    pub fn create(arch: EmulatorArch) -> Box<dyn Emulator> {
        Box::new(SimpleInterpreter::new(arch))
    }
}

// ── ExecutionResult ───────────────────────────────────────────────────────────

/// Why emulation stopped.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExitReason {
    Normal,
    Breakpoint,
    Timeout,
    InvalidInsn,
    MemFault,
    CountLimit,
    UserStop,
}

/// Recorded memory access during emulation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemAccess {
    pub addr: u64,
    pub size: usize,
    pub value: u64,
    pub is_write: bool,
}

/// Recorded syscall/interrupt event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyscallEntry {
    pub pc: u64,
    pub number: u64,
    pub args: Vec<u64>,
}

/// Full result of an emulation run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionResult {
    pub exit_reason: ExitReason,
    pub final_registers: HashMap<u32, u64>,
    pub memory_accesses: Vec<MemAccess>,
    pub syscall_log: Vec<SyscallEntry>,
    pub return_value: Option<u64>,
    pub instructions_executed: u64,
}

impl ExecutionResult {
    #[must_use]
    pub const fn new_normal(regs: HashMap<u32, u64>, ret: Option<u64>) -> Self {
        Self {
            exit_reason: ExitReason::Normal,
            final_registers: regs,
            memory_accesses: vec![],
            syscall_log: vec![],
            return_value: ret,
            instructions_executed: 0,
        }
    }
}

// ── OsType ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OsType {
    Windows,
    Linux,
    MacOs,
    Bare,
}

// ── Trace ────────────────────────────────────────────────────────────────────

/// Instruction-level execution trace.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Trace {
    pub entries: Vec<TraceEntry>,
}

impl Trace {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
    pub fn push(&mut self, e: TraceEntry) {
        self.entries.push(e);
    }
    #[must_use]
    pub const fn len(&self) -> usize {
        self.entries.len()
    }
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
    #[must_use]
    pub fn unique_pcs(&self) -> HashSet<u64> {
        self.entries.iter().map(|e| e.pc).collect()
    }
}

/// Convert a u64 to f64 (may lose precision for values above 2^53).
fn u64_to_f64(v: u64) -> f64 {
    // Split into high and low 32-bit halves to avoid the direct u64 -> f64 cast.
    let hi = u32::try_from(v >> 32).unwrap_or(u32::MAX);
    let lo = u32::try_from(v & 0xFFFF_FFFF).unwrap_or(u32::MAX);
    f64::from(hi).mul_add(4_294_967_296.0, f64::from(lo))
}

/// Convert a usize to f64 (may lose precision on 64-bit targets for very large values).
fn usize_to_f64(v: usize) -> f64 {
    u64_to_f64(u64::try_from(v).unwrap_or(u64::MAX))
}

// ── EmuStats ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EmuStats {
    pub insns_executed: u64,
    pub mem_reads: u64,
    pub mem_writes: u64,
    pub branches_taken: u64,
    pub branches_not_taken: u64,
    pub interrupts: u64,
    pub mem_faults: u64,
    pub hook_callbacks: u64,
    pub unique_pcs: u64,
}

impl EmuStats {
    pub fn reset(&mut self) {
        *self = Self::default();
    }
    pub const fn merge(&mut self, other: &Self) {
        self.insns_executed += other.insns_executed;
        self.mem_reads += other.mem_reads;
        self.mem_writes += other.mem_writes;
        self.branches_taken += other.branches_taken;
        self.branches_not_taken += other.branches_not_taken;
        self.interrupts += other.interrupts;
        self.mem_faults += other.mem_faults;
        self.hook_callbacks += other.hook_callbacks;
        self.unique_pcs += other.unique_pcs;
    }
    #[must_use]
    pub fn ipc(&self) -> f64 {
        let a = self.mem_reads + self.mem_writes;
        if a == 0 {
            0.0
        } else {
            u64_to_f64(self.insns_executed) / u64_to_f64(a)
        }
    }
    #[must_use]
    pub fn branch_ratio(&self) -> f64 {
        let t = self.branches_taken + self.branches_not_taken;
        if t == 0 {
            0.0
        } else {
            u64_to_f64(self.branches_taken) / u64_to_f64(t)
        }
    }
}

// ── CoverageMap ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
pub struct CoverageMap {
    hits: HashMap<u64, u32>,
}

impl CoverageMap {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
    pub fn record(&mut self, addr: u64) {
        *self.hits.entry(addr).or_insert(0) += 1;
    }
    #[must_use]
    pub fn unique_count(&self) -> usize {
        self.hits.len()
    }
    #[must_use]
    pub fn hit_count(&self, addr: u64) -> u32 {
        self.hits.get(&addr).copied().unwrap_or(0)
    }
    #[must_use]
    pub fn covered_addresses(&self) -> Vec<u64> {
        let mut v: Vec<u64> = self.hits.keys().copied().collect();
        v.sort_unstable();
        v
    }
    pub fn merge(&mut self, other: &Self) {
        for (&a, &c) in &other.hits {
            *self.hits.entry(a).or_insert(0) += c;
        }
    }
    #[must_use]
    pub fn singleton_addresses(&self) -> Vec<u64> {
        let mut v: Vec<u64> = self
            .hits
            .iter()
            .filter(|(_, c)| **c == 1)
            .map(|(&a, _)| a)
            .collect();
        v.sort_unstable();
        v
    }
    #[must_use]
    pub fn is_covered(&self, addr: u64) -> bool {
        self.hits.contains_key(&addr)
    }
    pub fn reset(&mut self) {
        self.hits.clear();
    }
}

// ── EmuCoverageTracker ────────────────────────────────────────────────────────

#[derive(Debug, Default)]
pub struct EmuCoverageTracker {
    visited: HashSet<u64>,
}

impl EmuCoverageTracker {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
    pub fn record(&mut self, addr: u64) {
        self.visited.insert(addr);
    }
    #[must_use]
    pub fn unique_count(&self) -> usize {
        self.visited.len()
    }
    #[must_use]
    pub fn was_visited(&self, addr: u64) -> bool {
        self.visited.contains(&addr)
    }
    #[must_use]
    pub fn coverage_pct(&self, start: u64, end: u64) -> f64 {
        if end <= start {
            return 0.0;
        }
        let total = u64_to_f64(end - start);
        let hit = usize_to_f64(
            self.visited
                .iter()
                .filter(|&&a| a >= start && a < end)
                .count(),
        );
        (hit / total) * 100.0
    }
    #[must_use]
    pub fn visited_sorted(&self) -> Vec<u64> {
        let mut v: Vec<u64> = self.visited.iter().copied().collect();
        v.sort_unstable();
        v
    }
    pub fn reset(&mut self) {
        self.visited.clear();
    }
}

// ── CoverageCollector ─────────────────────────────────────────────────────────

/// Hooks-based basic-block coverage collector.
pub struct CoverageCollector {
    coverage: CoverageMap,
}

impl CoverageCollector {
    #[must_use]
    pub fn new() -> Self {
        Self {
            coverage: CoverageMap::new(),
        }
    }
    /// Install a code hook that records every PC. Returns the hook handle.
    pub fn install(&self, _emu: &mut dyn Emulator, _begin: u64, _end: u64) {
        // In a real impl, would call emu.add_code_hook(...).
        // Stub for interface completeness.
    }
    #[must_use]
    pub const fn coverage(&self) -> &CoverageMap {
        &self.coverage
    }
    pub fn record(&mut self, addr: u64) {
        self.coverage.record(addr);
    }
}

impl Default for CoverageCollector {
    fn default() -> Self {
        Self::new()
    }
}

// ── MemoryDumper ──────────────────────────────────────────────────────────────

/// Records all memory writes for later replay or diffing.
#[derive(Debug, Default)]
pub struct MemoryDumper {
    writes: Vec<(u64, Vec<u8>)>,
}

impl MemoryDumper {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
    pub fn record_write(&mut self, addr: u64, data: Vec<u8>) {
        self.writes.push((addr, data));
    }
    #[must_use]
    pub fn writes(&self) -> &[(u64, Vec<u8>)] {
        &self.writes
    }
    pub fn clear(&mut self) {
        self.writes.clear();
    }
    /// Replay all recorded writes into an emulator.
    ///
    /// # Errors
    /// Returns `EmulatorError` if a write fails.
    pub fn replay(&self, emu: &mut dyn Emulator) -> Result<(), EmulatorError> {
        for (addr, data) in &self.writes {
            emu.write_memory(*addr, data)?;
        }
        Ok(())
    }
}

// ── I/O port model ────────────────────────────────────────────────────────────

pub trait IoPortHandler: Send + Sync {
    fn read(&self, port: u16) -> u32;
    fn write(&self, port: u16, value: u32);
}

pub struct IoPortMap {
    exact: HashMap<u16, Box<dyn IoPortHandler>>,
    ranges: Vec<(u16, u16, Box<dyn IoPortHandler>)>,
    default_read_val: u32,
}

impl IoPortMap {
    #[must_use]
    pub fn new() -> Self {
        Self {
            exact: HashMap::new(),
            ranges: Vec::new(),
            default_read_val: 0xFF,
        }
    }
    pub const fn set_default_read(&mut self, val: u32) {
        self.default_read_val = val;
    }
    pub fn register_exact(&mut self, port: u16, handler: Box<dyn IoPortHandler>) {
        self.exact.insert(port, handler);
    }
    /// # Panics
    /// Panics if `first > last`.
    pub fn register_range(&mut self, first: u16, last: u16, handler: Box<dyn IoPortHandler>) {
        assert!(first <= last);
        self.ranges.push((first, last, handler));
    }
    #[must_use]
    pub fn read(&self, port: u16) -> u32 {
        if let Some(h) = self.exact.get(&port) {
            return h.read(port);
        }
        for (f, l, h) in &self.ranges {
            if port >= *f && port <= *l {
                return h.read(port);
            }
        }
        self.default_read_val
    }
    pub fn write(&self, port: u16, value: u32) {
        if let Some(h) = self.exact.get(&port) {
            h.write(port, value);
            return;
        }
        for (f, l, h) in &self.ranges {
            if port >= *f && port <= *l {
                h.write(port, value);
                return;
            }
        }
    }
}

impl Default for IoPortMap {
    fn default() -> Self {
        Self::new()
    }
}

// ── MMIO ─────────────────────────────────────────────────────────────────────

pub trait MmioDevice: Send + Sync {
    fn mmio_read(&self, offset: u64, size: usize) -> u64;
    fn mmio_write(&mut self, offset: u64, size: usize, value: u64);
    fn name(&self) -> &str;
}

pub struct MmioRegion {
    pub base: u64,
    pub size: u64,
    pub device: Box<dyn MmioDevice>,
}

impl MmioRegion {
    #[must_use]
    pub fn new(base: u64, size: u64, device: Box<dyn MmioDevice>) -> Self {
        Self { base, size, device }
    }
    #[must_use]
    pub const fn contains(&self, addr: u64) -> bool {
        addr >= self.base && addr < self.base + self.size
    }
    #[must_use]
    pub const fn offset_of(&self, addr: u64) -> u64 {
        addr - self.base
    }
}

pub struct MmioMap {
    regions: Vec<MmioRegion>,
}

impl MmioMap {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            regions: Vec::new(),
        }
    }
    /// # Errors
    /// Returns an error string if `region` overlaps an existing region.
    pub fn register(&mut self, region: MmioRegion) -> Result<(), String> {
        for r in &self.regions {
            if region.base < r.base + r.size && region.base + region.size > r.base {
                return Err(format!(
                    "MMIO overlap: 0x{:x}+0x{:x} vs '{}'",
                    region.base,
                    region.size,
                    r.device.name()
                ));
            }
        }
        self.regions.push(region);
        Ok(())
    }
    #[must_use]
    pub fn find(&self, addr: u64) -> Option<usize> {
        self.regions.iter().position(|r| r.contains(addr))
    }
    #[must_use]
    pub fn read(&self, addr: u64, size: usize) -> Option<u64> {
        let i = self.find(addr)?;
        let r = &self.regions[i];
        Some(r.device.mmio_read(r.offset_of(addr), size))
    }
    pub fn write(&mut self, addr: u64, size: usize, value: u64) -> bool {
        if let Some(i) = self.find(addr) {
            let b = self.regions[i].base;
            self.regions[i].device.mmio_write(addr - b, size, value);
            true
        } else {
            false
        }
    }
}

impl Default for MmioMap {
    fn default() -> Self {
        Self::new()
    }
}

// ── Interrupt model ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterruptVector {
    pub number: u32,
    pub handler_addr: u64,
    pub description: String,
}

pub struct InterruptController {
    vectors: HashMap<u32, InterruptVector>,
    pending: Vec<u32>,
    enabled: bool,
}

impl InterruptController {
    #[must_use]
    pub fn new() -> Self {
        Self {
            vectors: HashMap::new(),
            pending: Vec::new(),
            enabled: true,
        }
    }
    pub fn register_vector(&mut self, vector: InterruptVector) {
        self.vectors.insert(vector.number, vector);
    }
    pub fn raise(&mut self, number: u32) {
        if self.enabled {
            self.pending.push(number);
        }
    }
    #[must_use]
    pub fn next_pending(&mut self) -> Option<InterruptVector> {
        let n = self.pending.first().copied()?;
        self.pending.remove(0);
        self.vectors.get(&n).cloned()
    }
    pub const fn enable(&mut self) {
        self.enabled = true;
    }
    pub const fn disable(&mut self) {
        self.enabled = false;
    }
    #[must_use]
    pub const fn is_enabled(&self) -> bool {
        self.enabled
    }
    #[must_use]
    pub const fn pending_count(&self) -> usize {
        self.pending.len()
    }
}

impl Default for InterruptController {
    fn default() -> Self {
        Self::new()
    }
}

// ── Exception model ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ExceptionKind {
    DivideByZero,
    Debug,
    Nmi,
    Breakpoint,
    Overflow,
    BoundRange,
    InvalidOpcode,
    DeviceNotAvailable,
    DoubleFault,
    InvalidTss,
    SegmentNotPresent,
    StackSegmentFault,
    GeneralProtection,
    PageFault,
    FloatingPoint,
    AlignmentCheck,
    MachineCheck,
    SimdFloat,
    Virtualisation,
    Unknown(u32),
}

impl ExceptionKind {
    #[must_use]
    pub const fn vector(self) -> u32 {
        match self {
            Self::DivideByZero => 0,
            Self::Debug => 1,
            Self::Nmi => 2,
            Self::Breakpoint => 3,
            Self::Overflow => 4,
            Self::BoundRange => 5,
            Self::InvalidOpcode => 6,
            Self::DeviceNotAvailable => 7,
            Self::DoubleFault => 8,
            Self::InvalidTss => 10,
            Self::SegmentNotPresent => 11,
            Self::StackSegmentFault => 12,
            Self::GeneralProtection => 13,
            Self::PageFault => 14,
            Self::FloatingPoint => 16,
            Self::AlignmentCheck => 17,
            Self::MachineCheck => 18,
            Self::SimdFloat => 19,
            Self::Virtualisation => 20,
            Self::Unknown(n) => n,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CpuException {
    pub kind: ExceptionKind,
    pub fault_addr: u64,
    pub error_code: Option<u64>,
}

impl CpuException {
    #[must_use]
    pub const fn new(kind: ExceptionKind, fault_addr: u64) -> Self {
        Self {
            kind,
            fault_addr,
            error_code: None,
        }
    }
    #[must_use]
    pub const fn with_error_code(mut self, code: u64) -> Self {
        self.error_code = Some(code);
        self
    }
}

// ── Device emulation ──────────────────────────────────────────────────────────

pub trait EmulatedDevice: Send + Sync {
    fn name(&self) -> &str;
    fn reset(&mut self);
    fn tick(&mut self, cycles: u64);
    fn irq_pending(&self) -> bool;
    fn irq_vector(&self) -> Option<u32>;
}

pub struct NullDevice {
    device_name: String,
}
impl NullDevice {
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            device_name: name.into(),
        }
    }
}
impl EmulatedDevice for NullDevice {
    fn name(&self) -> &str {
        &self.device_name
    }
    fn reset(&mut self) {}
    fn tick(&mut self, _: u64) {}
    fn irq_pending(&self) -> bool {
        false
    }
    fn irq_vector(&self) -> Option<u32> {
        None
    }
}

// ── RegisterFile ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterFile {
    regs: Vec<u64>,
    names: Vec<String>,
}

impl RegisterFile {
    #[must_use]
    pub fn new(names: Vec<String>) -> Self {
        let c = names.len();
        Self {
            regs: vec![0; c],
            names,
        }
    }
    #[must_use]
    pub const fn len(&self) -> usize {
        self.regs.len()
    }
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.regs.is_empty()
    }
    /// # Errors
    /// Returns an error if `i` is out of bounds.
    pub fn read(&self, i: usize) -> Result<u64, String> {
        self.regs
            .get(i)
            .copied()
            .ok_or_else(|| format!("reg {i} oob"))
    }
    /// # Errors
    /// Returns an error if `i` is out of bounds.
    pub fn write(&mut self, i: usize, v: u64) -> Result<(), String> {
        if i < self.regs.len() {
            self.regs[i] = v;
            Ok(())
        } else {
            Err(format!("reg {i} oob"))
        }
    }
    #[must_use]
    pub fn name_of(&self, i: usize) -> Option<&str> {
        self.names.get(i).map(String::as_str)
    }
    #[must_use]
    pub fn index_of(&self, name: &str) -> Option<usize> {
        let lower = name.to_ascii_lowercase();
        self.names
            .iter()
            .position(|n| n.to_ascii_lowercase() == lower)
    }
    pub fn zero_all(&mut self) {
        self.regs.iter_mut().for_each(|r| *r = 0);
    }
    #[must_use]
    pub fn snapshot(&self) -> Vec<u64> {
        self.regs.clone()
    }
    /// # Errors
    /// Returns an error if `snap` length does not match the register count.
    pub fn restore(&mut self, snap: &[u64]) -> Result<(), String> {
        if snap.len() != self.regs.len() {
            return Err(format!(
                "snapshot len {} != {}",
                snap.len(),
                self.regs.len()
            ));
        }
        self.regs.copy_from_slice(snap);
        Ok(())
    }
}

// ── FlatMemory ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct FlatMemory {
    data: Vec<u8>,
    base: u64,
    perms: MemPerms,
}

impl FlatMemory {
    #[must_use]
    pub fn new(base: u64, size: usize, perms: MemPerms) -> Self {
        Self {
            data: vec![0u8; size],
            base,
            perms,
        }
    }
    /// # Panics
    /// Panics if `bytes.len() > self.size()`.
    pub fn load(&mut self, bytes: &[u8]) {
        assert!(bytes.len() <= self.data.len());
        self.data[..bytes.len()].copy_from_slice(bytes);
    }
    /// # Errors
    /// Returns `EmulatorError::MemFault` on permission failure or out-of-bounds.
    pub fn read(&self, addr: u64, len: usize) -> Result<Vec<u8>, EmulatorError> {
        if !self.perms.contains(MemPerms::READ) {
            return Err(EmulatorError::MemFault {
                addr,
                op: "read".into(),
            });
        }
        let o = addr
            .checked_sub(self.base)
            .and_then(|o| usize::try_from(o).ok())
            .ok_or_else(|| EmulatorError::MemFault {
                addr,
                op: "read-underflow".into(),
            })?;
        if o + len > self.data.len() {
            return Err(EmulatorError::MemFault {
                addr: addr + (self.data.len() - o) as u64,
                op: "read-oob".into(),
            });
        }
        Ok(self.data[o..o + len].to_vec())
    }
    /// # Errors
    /// Returns `EmulatorError::MemFault` on permission failure or out-of-bounds.
    pub fn write(&mut self, addr: u64, data: &[u8]) -> Result<(), EmulatorError> {
        if !self.perms.contains(MemPerms::WRITE) {
            return Err(EmulatorError::MemFault {
                addr,
                op: "write".into(),
            });
        }
        let o = addr
            .checked_sub(self.base)
            .and_then(|o| usize::try_from(o).ok())
            .ok_or_else(|| EmulatorError::MemFault {
                addr,
                op: "write-underflow".into(),
            })?;
        if o + data.len() > self.data.len() {
            return Err(EmulatorError::MemFault {
                addr: addr + (self.data.len() - o) as u64,
                op: "write-oob".into(),
            });
        }
        self.data[o..o + data.len()].copy_from_slice(data);
        Ok(())
    }
    #[must_use]
    pub const fn size(&self) -> usize {
        self.data.len()
    }
    #[must_use]
    pub const fn base(&self) -> u64 {
        self.base
    }
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }
}

// ── Snapshot manager ──────────────────────────────────────────────────────────

pub struct SnapshotManager {
    snapshots: HashMap<SnapshotId, (String, Vec<u8>)>,
    counter: u64,
}

impl SnapshotManager {
    #[must_use]
    pub fn new() -> Self {
        Self {
            snapshots: HashMap::new(),
            counter: 0,
        }
    }
    /// # Errors
    /// Returns `EmulatorError` if `emu.context_save` fails.
    pub fn save(
        &mut self,
        emu: &dyn Emulator,
        label: impl Into<String>,
    ) -> Result<SnapshotId, EmulatorError> {
        self.counter += 1;
        let id = SnapshotId(self.counter);
        self.snapshots
            .insert(id, (label.into(), emu.context_save()?));
        Ok(id)
    }
    /// # Errors
    /// Returns `EmulatorError::InvalidArg` if `id` is unknown, or restore fails.
    pub fn restore(&self, emu: &mut dyn Emulator, id: SnapshotId) -> Result<(), EmulatorError> {
        let (_, bytes) = self
            .snapshots
            .get(&id)
            .ok_or_else(|| EmulatorError::InvalidArg(format!("snapshot {id:?} not found")))?;
        emu.context_restore(bytes)
    }
    #[must_use]
    pub fn list(&self) -> Vec<(SnapshotId, &str)> {
        let mut v: Vec<_> = self
            .snapshots
            .iter()
            .map(|(&id, (l, _))| (id, l.as_str()))
            .collect();
        v.sort_by_key(|(id, _)| id.0);
        v
    }
    /// # Errors
    /// Returns `EmulatorError::InvalidArg` if `id` is unknown.
    pub fn remove(&mut self, id: SnapshotId) -> Result<(), EmulatorError> {
        self.snapshots
            .remove(&id)
            .ok_or_else(|| EmulatorError::InvalidArg(format!("snapshot {id:?} not found")))?;
        Ok(())
    }
    #[must_use]
    pub fn count(&self) -> usize {
        self.snapshots.len()
    }
}

impl Default for SnapshotManager {
    fn default() -> Self {
        Self::new()
    }
}

// ── EmuSnapshot / EmuCheckpointManager ───────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmuSnapshot {
    pub cpu_context: Vec<u8>,
    pub memory_pages: BTreeMap<u64, Vec<u8>>,
}

pub struct EmuCheckpointManager {
    snapshots: HashMap<u64, EmuSnapshot>,
    next_id: u64,
}

impl EmuCheckpointManager {
    #[must_use]
    pub fn new() -> Self {
        Self {
            snapshots: HashMap::new(),
            next_id: 1,
        }
    }
    /// # Errors
    /// Returns `EmulatorError` if context save or memory read fails.
    pub fn save_checkpoint(&mut self, emu: &dyn Emulator) -> Result<u64, EmulatorError> {
        let cpu_context = emu.context_save()?;
        let mut memory_pages = BTreeMap::new();
        for region in emu.regions() {
            let data = emu.read_memory(region.start, region.size)?;
            memory_pages.insert(region.start, data);
        }
        let id = self.next_id;
        self.next_id += 1;
        self.snapshots.insert(
            id,
            EmuSnapshot {
                cpu_context,
                memory_pages,
            },
        );
        Ok(id)
    }
    /// # Errors
    /// Returns `EmulatorError` if context restore or memory write fails.
    pub fn restore_checkpoint(
        &self,
        id: u64,
        emu: &mut dyn Emulator,
    ) -> Result<bool, EmulatorError> {
        let Some(snap) = self.snapshots.get(&id) else {
            return Ok(false);
        };
        emu.context_restore(&snap.cpu_context)?;
        for (base, data) in &snap.memory_pages {
            emu.write_memory(*base, data)?;
        }
        Ok(true)
    }
    #[must_use]
    pub fn checkpoint_count(&self) -> usize {
        self.snapshots.len()
    }
    pub fn delete_checkpoint(&mut self, id: u64) -> bool {
        self.snapshots.remove(&id).is_some()
    }
}

impl Default for EmuCheckpointManager {
    fn default() -> Self {
        Self::new()
    }
}

// ── Instruction trace ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceEntry {
    pub pc: u64,
    pub size: u32,
    pub bytes: Vec<u8>,
    pub disasm: String,
}

pub struct InsnTrace {
    entries: VecDeque<TraceEntry>,
    capacity: usize,
}

impl InsnTrace {
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            entries: VecDeque::with_capacity(capacity.min(1_000_000)),
            capacity,
        }
    }
    pub fn push(&mut self, entry: TraceEntry) {
        if self.entries.len() == self.capacity {
            self.entries.pop_front();
        }
        self.entries.push_back(entry);
    }
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
    #[must_use]
    pub fn last_n(&self, n: usize) -> Vec<&TraceEntry> {
        self.entries.iter().rev().take(n).collect()
    }
    pub fn clear(&mut self) {
        self.entries.clear();
    }
    pub fn iter(&self) -> impl Iterator<Item = &TraceEntry> {
        self.entries.iter()
    }
}

// ── CoverageEmu ───────────────────────────────────────────────────────────────

pub struct CoverageEmu<'a> {
    emulator: &'a mut dyn Emulator,
    coverage: CoverageMap,
    stats: EmuStats,
}

impl<'a> CoverageEmu<'a> {
    pub fn new(emulator: &'a mut dyn Emulator) -> Self {
        Self {
            emulator,
            coverage: CoverageMap::new(),
            stats: EmuStats::default(),
        }
    }
    /// # Errors
    /// Returns `EmulatorError` if hook installation or emulator start fails.
    ///
    /// # Panics
    /// Panics if internal `Mutex` is poisoned.
    pub fn run(
        &mut self,
        begin: u64,
        until: u64,
        timeout_ms: u64,
        max_insns: u64,
    ) -> Result<(), EmulatorError> {
        use std::sync::{Arc, Mutex};
        let cov = Arc::new(Mutex::new(CoverageMap::new()));
        let stat = Arc::new(Mutex::new(EmuStats::default()));
        let cov2 = Arc::clone(&cov);
        let stat2 = Arc::clone(&stat);
        let handle = self.emulator.add_code_hook(
            begin,
            until,
            Box::new(move |pc, _| {
                cov2.lock().unwrap().record(pc);
                stat2.lock().unwrap().insns_executed += 1;
            }),
        )?;
        let result = self.emulator.start(begin, until, timeout_ms, max_insns);
        if let Err(e) = self.emulator.remove_hook(handle) {
            eprintln!("rustre-emu: CoverageEmu::run — remove_hook failed: {e}");
        }
        match Arc::try_unwrap(cov) {
            Ok(c) => self.coverage.merge(&c.into_inner().unwrap()),
            Err(arc) => self.coverage.merge(&arc.lock().unwrap().clone()),
        }
        match Arc::try_unwrap(stat) {
            Ok(s) => self.stats.merge(&s.into_inner().unwrap()),
            Err(arc) => self.stats.merge(&arc.lock().unwrap().clone()),
        }
        result
    }
    #[must_use]
    pub const fn coverage(&self) -> &CoverageMap {
        &self.coverage
    }
    #[must_use]
    pub const fn stats(&self) -> &EmuStats {
        &self.stats
    }
    #[must_use]
    pub fn into_coverage(self) -> CoverageMap {
        self.coverage
    }
}

// ── EmuSession ────────────────────────────────────────────────────────────────

pub struct EmuSession {
    emulator: Box<dyn Emulator>,
    stats: EmuStats,
    snapshots: SnapshotManager,
    trace: InsnTrace,
    coverage: CoverageMap,
}

impl EmuSession {
    #[must_use]
    pub fn new(emulator: Box<dyn Emulator>, trace_cap: usize) -> Self {
        Self {
            emulator,
            stats: EmuStats::default(),
            snapshots: SnapshotManager::new(),
            trace: InsnTrace::new(trace_cap),
            coverage: CoverageMap::new(),
        }
    }
    #[must_use]
    pub fn emulator(&self) -> &dyn Emulator {
        self.emulator.as_ref()
    }
    pub fn emulator_mut(&mut self) -> &mut dyn Emulator {
        self.emulator.as_mut()
    }
    #[must_use]
    pub const fn stats(&self) -> &EmuStats {
        &self.stats
    }
    #[must_use]
    pub const fn coverage(&self) -> &CoverageMap {
        &self.coverage
    }
    #[must_use]
    pub const fn trace(&self) -> &InsnTrace {
        &self.trace
    }
    /// # Errors
    /// Returns `EmulatorError` if context save fails.
    pub fn save_snapshot(&mut self, label: impl Into<String>) -> Result<SnapshotId, EmulatorError> {
        self.snapshots.save(self.emulator.as_ref(), label)
    }
    /// # Errors
    /// Returns `EmulatorError::InvalidArg` if `id` is unknown, or restoration fails.
    pub fn restore_snapshot(&mut self, id: SnapshotId) -> Result<(), EmulatorError> {
        self.snapshots.restore(self.emulator.as_mut(), id)
    }
    /// # Errors
    /// Returns `EmulatorError` if hook installation or emulator start fails.
    ///
    /// # Panics
    /// Panics if internal `Mutex` is poisoned.
    pub fn run(
        &mut self,
        begin: u64,
        until: u64,
        timeout_ms: u64,
        max_insns: u64,
    ) -> Result<(), EmulatorError> {
        use std::sync::{Arc, Mutex};
        let cov = Arc::new(Mutex::new(CoverageMap::new()));
        let stat = Arc::new(Mutex::new(EmuStats::default()));
        let cov2 = Arc::clone(&cov);
        let stat2 = Arc::clone(&stat);
        let handle = self.emulator.add_code_hook(
            begin,
            until,
            Box::new(move |pc, _| {
                cov2.lock().unwrap().record(pc);
                stat2.lock().unwrap().insns_executed += 1;
            }),
        )?;
        let result = self.emulator.start(begin, until, timeout_ms, max_insns);
        if let Err(e) = self.emulator.remove_hook(handle) {
            eprintln!("rustre-emu: EmuSession::run — remove_hook failed: {e}");
        }
        match Arc::try_unwrap(cov) {
            Ok(c) => self.coverage.merge(&c.into_inner().unwrap()),
            Err(arc) => self.coverage.merge(&arc.lock().unwrap().clone()),
        }
        match Arc::try_unwrap(stat) {
            Ok(s) => self.stats.merge(&s.into_inner().unwrap()),
            Err(arc) => self.stats.merge(&arc.lock().unwrap().clone()),
        }
        result
    }
    #[must_use]
    pub fn list_snapshots(&self) -> Vec<(SnapshotId, &str)> {
        self.snapshots.list()
    }
}

// ── HookAction / EmuHookManager ──────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookAction {
    Continue,
    SkipInstruction,
    StopEmulation,
}

struct AddrHookEntry {
    callback: Box<dyn Fn(u64) -> HookAction + Send + Sync>,
}

pub struct EmuHookManager {
    hooks: HashMap<u64, Vec<AddrHookEntry>>,
}

impl EmuHookManager {
    #[must_use]
    pub fn new() -> Self {
        Self {
            hooks: HashMap::new(),
        }
    }
    pub fn register<F: Fn(u64) -> HookAction + Send + Sync + 'static>(
        &mut self,
        addr: u64,
        callback: F,
    ) {
        self.hooks.entry(addr).or_default().push(AddrHookEntry {
            callback: Box::new(callback),
        });
    }
    pub fn unregister(&mut self, addr: u64) -> usize {
        self.hooks.remove(&addr).map_or(0, |v| v.len())
    }
    #[must_use]
    pub fn dispatch(&self, addr: u64) -> HookAction {
        if let Some(entries) = self.hooks.get(&addr) {
            for e in entries {
                let a = (e.callback)(addr);
                if a != HookAction::Continue {
                    return a;
                }
            }
        }
        HookAction::Continue
    }
    #[must_use]
    pub fn hook_site_count(&self) -> usize {
        self.hooks.len()
    }
}

impl Default for EmuHookManager {
    fn default() -> Self {
        Self::new()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    fn make_x64() -> SimpleInterpreter {
        SimpleInterpreter::new(EmulatorArch::X86_64)
    }
    fn setup(emu: &mut SimpleInterpreter, base: u64, code: &[u8]) {
        let size = code.len().max(0x1000);
        emu.map_memory(base, size, MemPerms::ALL).unwrap();
        emu.write_memory(base, code).unwrap();
    }

    // ── arch ─────────────────────────────────────────────────────────────────

    #[test]
    fn test_arch_name() {
        assert_eq!(EmulatorArch::X86_64.name(), "x86-64");
        assert_eq!(EmulatorArch::Arm64.name(), "arm64");
    }
    #[test]
    fn test_arch_pointer_size() {
        assert_eq!(EmulatorArch::X86_64.pointer_size(), 8);
        assert_eq!(EmulatorArch::X86_32.pointer_size(), 4);
        assert_eq!(EmulatorArch::X86_16.pointer_size(), 2);
    }
    #[test]
    fn test_arch_is_64bit() {
        assert!(EmulatorArch::X86_64.is_64bit());
        assert!(!EmulatorArch::X86_32.is_64bit());
    }
    #[test]
    fn test_arch_is_x86() {
        assert!(EmulatorArch::X86_64.is_x86());
        assert!(!EmulatorArch::Arm64.is_x86());
    }

    // ── memory ────────────────────────────────────────────────────────────────

    #[test]
    fn test_map_write_read() {
        let mut e = make_x64();
        e.map_memory(0x1000, 0x1000, MemPerms::ALL).unwrap();
        e.write_memory(0x1000, &[0xDE, 0xAD, 0xBE, 0xEF]).unwrap();
        assert_eq!(e.read_memory(0x1000, 4).unwrap(), [0xDE, 0xAD, 0xBE, 0xEF]);
    }
    #[test]
    fn test_read_fault() {
        let e = make_x64();
        assert!(matches!(
            e.read_memory(0xDEAD, 4).unwrap_err(),
            EmulatorError::MemFault { .. }
        ));
    }
    #[test]
    fn test_unmap() {
        let mut e = make_x64();
        e.map_memory(0x2000, 0x1000, MemPerms::READ).unwrap();
        e.unmap_memory(0x2000).unwrap();
        assert_eq!(e.regions().len(), 0);
    }
    #[test]
    fn test_overlap_fails() {
        let mut e = make_x64();
        e.map_memory(0x1000, 0x2000, MemPerms::ALL).unwrap();
        assert!(matches!(
            e.map_memory(0x1500, 0x1000, MemPerms::ALL).unwrap_err(),
            EmulatorError::InvalidArg(_)
        ));
    }
    #[test]
    fn test_unmap_nonexistent() {
        let mut e = make_x64();
        assert!(matches!(
            e.unmap_memory(0x9999).unwrap_err(),
            EmulatorError::InvalidArg(_)
        ));
    }

    // ── registers ─────────────────────────────────────────────────────────────

    #[test]
    fn test_register_rw() {
        let mut e = make_x64();
        e.write_register(x86_regs::RAX, 0xDEAD_BEEF).unwrap();
        assert_eq!(e.read_register(x86_regs::RAX).unwrap(), 0xDEAD_BEEF);
    }

    // ── execution ─────────────────────────────────────────────────────────────

    #[test]
    fn test_nop_execution() {
        let mut e = make_x64();
        setup(&mut e, 0x1000, &[0x90, 0x90, 0x90, 0x90, 0xF4]);
        e.start(0x1000, 0x2000, 0, 0).unwrap();
        assert_eq!(e.read_register(x86_regs::RIP).unwrap(), 0x1004);
    }
    #[test]
    fn test_mov_imm_eax() {
        let mut e = make_x64();
        setup(&mut e, 0x1000, &[0xB8, 0x42, 0x00, 0x00, 0x00, 0xF4]);
        e.start(0x1000, 0x2000, 0, 0).unwrap();
        assert_eq!(e.read_register(x86_regs::RAX).unwrap(), 0x42);
    }
    #[test]
    fn test_add_eax() {
        let mut e = make_x64();
        e.write_register(x86_regs::RAX, 10).unwrap();
        setup(&mut e, 0x1000, &[0x05, 0x05, 0x00, 0x00, 0x00, 0xF4]);
        e.start(0x1000, 0x2000, 0, 0).unwrap();
        assert_eq!(e.read_register(x86_regs::RAX).unwrap(), 15);
    }
    #[test]
    fn test_sub_eax() {
        let mut e = make_x64();
        e.write_register(x86_regs::RAX, 20).unwrap();
        setup(&mut e, 0x1000, &[0x2D, 0x07, 0x00, 0x00, 0x00, 0xF4]);
        e.start(0x1000, 0x2000, 0, 0).unwrap();
        assert_eq!(e.read_register(x86_regs::RAX).unwrap(), 13);
    }
    #[test]
    fn test_xor_eax() {
        let mut e = make_x64();
        e.write_register(x86_regs::RAX, 0xFF).unwrap();
        setup(&mut e, 0x1000, &[0x35, 0xFF, 0x00, 0x00, 0x00, 0xF4]);
        e.start(0x1000, 0x2000, 0, 0).unwrap();
        assert_eq!(e.read_register(x86_regs::RAX).unwrap(), 0);
    }
    #[test]
    fn test_push_pop() {
        let mut e = make_x64();
        e.map_memory(0x8000, 0x1000, MemPerms::READ | MemPerms::WRITE)
            .unwrap();
        e.write_register(x86_regs::RSP, 0x8800).unwrap();
        setup(&mut e, 0x1000, &[0x6A, 0x7F, 0x58, 0xF4]);
        e.start(0x1000, 0x2000, 0, 0).unwrap();
        assert_eq!(e.read_register(x86_regs::RAX).unwrap(), 0x7F);
    }
    #[test]
    fn test_jmp_rel8() {
        let mut e = make_x64();
        setup(
            &mut e,
            0x1000,
            &[
                0xEB, 0x03, 0x90, 0x90, 0x90, 0xB8, 0x99, 0x00, 0x00, 0x00, 0xF4,
            ],
        );
        e.start(0x1000, 0x2000, 0, 0).unwrap();
        assert_eq!(e.read_register(x86_regs::RAX).unwrap(), 0x99);
    }
    #[test]
    fn test_count_limit() {
        let mut e = make_x64();
        setup(&mut e, 0x1000, &[0x90, 0xEB, 0xFD]);
        e.start(0x1000, 0x9999, 0, 10).unwrap();
    }
    #[test]
    fn test_invalid_insn_0f_ff() {
        let mut e = make_x64();
        setup(&mut e, 0x1000, &[0x0F, 0xFF]);
        assert!(matches!(
            e.start(0x1000, 0x2000, 0, 0).unwrap_err(),
            EmulatorError::InvalidInsn { .. }
        ));
    }

    // ── hooks ─────────────────────────────────────────────────────────────────

    #[test]
    fn test_code_hook() {
        let mut e = make_x64();
        let c = Arc::new(Mutex::new(0u64));
        let c2 = Arc::clone(&c);
        setup(&mut e, 0x1000, &[0x90, 0x90, 0x90, 0xF4]);
        e.add_code_hook(
            0x1000,
            0x2000,
            Box::new(move |_, _| {
                *c2.lock().unwrap() += 1;
            }),
        )
        .unwrap();
        e.start(0x1000, 0x2000, 0, 0).unwrap();
        assert!(*c.lock().unwrap() >= 3);
    }
    #[test]
    fn test_mem_write_hook() {
        let mut e = make_x64();
        let t = Arc::new(Mutex::new(false));
        let t2 = Arc::clone(&t);
        e.map_memory(0x1000, 0x1000, MemPerms::ALL).unwrap();
        e.add_mem_hook(
            HookKind::MemWrite,
            Box::new(move |_, _, _| {
                *t2.lock().unwrap() = true;
            }),
        )
        .unwrap();
        e.write_memory(0x1000, &[0xAA]).unwrap();
        assert!(*t.lock().unwrap());
    }
    #[test]
    fn test_remove_hook() {
        let mut e = make_x64();
        e.map_memory(0x1000, 0x100, MemPerms::ALL).unwrap();
        let h = e
            .add_mem_hook(HookKind::MemWrite, Box::new(|_, _, _| {}))
            .unwrap();
        e.remove_hook(h).unwrap();
        assert!(matches!(
            e.remove_hook(h).unwrap_err(),
            EmulatorError::HookError(_)
        ));
    }
    #[test]
    fn test_hook_uniqueness() {
        let mut e = make_x64();
        e.map_memory(0x1000, 0x100, MemPerms::ALL).unwrap();
        let h1 = e
            .add_mem_hook(HookKind::MemRead, Box::new(|_, _, _| {}))
            .unwrap();
        let h2 = e
            .add_mem_hook(HookKind::MemWrite, Box::new(|_, _, _| {}))
            .unwrap();
        assert_ne!(h1, h2);
    }

    // ── context save/restore ──────────────────────────────────────────────────

    #[test]
    fn test_context_save_restore() {
        let mut e = make_x64();
        e.write_register(x86_regs::RAX, 0xCAFE).unwrap();
        let ctx = e.context_save().unwrap();
        e.write_register(x86_regs::RAX, 0xDEAD).unwrap();
        e.context_restore(&ctx).unwrap();
        assert_eq!(e.read_register(x86_regs::RAX).unwrap(), 0xCAFE);
    }

    // ── regions ───────────────────────────────────────────────────────────────

    #[test]
    fn test_regions() {
        let mut e = make_x64();
        e.map_memory(0x1000, 0x1000, MemPerms::READ | MemPerms::EXEC)
            .unwrap();
        e.map_memory(0x5000, 0x2000, MemPerms::READ | MemPerms::WRITE)
            .unwrap();
        let r = e.regions();
        assert_eq!(r.len(), 2);
        assert_eq!(r[0].start, 0x1000);
    }
    #[test]
    fn test_mem_region_contains() {
        let r = MemRegion::new(0x1000, 0x1000, MemPerms::ALL);
        assert!(r.contains(0x1000));
        assert!(r.contains(0x1FFF));
        assert!(!r.contains(0x2000));
    }
    #[test]
    fn test_mem_region_label() {
        let r = MemRegion::new(0x1000, 0x100, MemPerms::READ).with_label("stack");
        assert_eq!(r.label.as_deref(), Some("stack"));
    }

    // ── factory ───────────────────────────────────────────────────────────────

    #[test]
    fn test_factory() {
        let e = EmulatorFactory::create(EmulatorArch::X86_64);
        assert_eq!(e.arch(), EmulatorArch::X86_64);
    }

    // ── EmuStats ──────────────────────────────────────────────────────────────

    #[test]
    fn test_stats_default() {
        let s = EmuStats::default();
        assert_eq!(s.insns_executed, 0);
        assert!(s.ipc().abs() < f64::EPSILON);
    }
    #[test]
    fn test_stats_merge() {
        let mut a = EmuStats {
            insns_executed: 10,
            mem_reads: 2,
            mem_writes: 3,
            ..Default::default()
        };
        a.merge(&EmuStats {
            insns_executed: 5,
            mem_reads: 1,
            mem_writes: 1,
            ..Default::default()
        });
        assert_eq!(a.insns_executed, 15);
        assert_eq!(a.mem_reads, 3);
    }
    #[test]
    fn test_stats_ipc() {
        let s = EmuStats {
            insns_executed: 100,
            mem_reads: 20,
            mem_writes: 30,
            ..Default::default()
        };
        assert!((s.ipc() - 2.0).abs() < 1e-9);
    }
    #[test]
    fn test_branch_ratio() {
        let s = EmuStats {
            branches_taken: 3,
            branches_not_taken: 1,
            ..Default::default()
        };
        assert!((s.branch_ratio() - 0.75).abs() < 1e-9);
    }

    // ── CoverageMap ───────────────────────────────────────────────────────────

    #[test]
    fn test_coverage_record() {
        let mut c = CoverageMap::new();
        c.record(0x1000);
        c.record(0x1000);
        c.record(0x2000);
        assert_eq!(c.unique_count(), 2);
        assert_eq!(c.hit_count(0x1000), 2);
    }
    #[test]
    fn test_coverage_merge() {
        let mut a = CoverageMap::new();
        a.record(0x1000);
        let mut b = CoverageMap::new();
        b.record(0x2000);
        b.record(0x1000);
        a.merge(&b);
        assert_eq!(a.unique_count(), 2);
    }
    #[test]
    fn test_coverage_singleton() {
        let mut c = CoverageMap::new();
        c.record(0x1000);
        c.record(0x1000);
        c.record(0x2000);
        assert_eq!(c.singleton_addresses(), vec![0x2000]);
    }
    #[test]
    fn test_coverage_reset() {
        let mut c = CoverageMap::new();
        c.record(0x1000);
        c.reset();
        assert_eq!(c.unique_count(), 0);
    }

    // ── EmuCoverageTracker ────────────────────────────────────────────────────

    #[test]
    fn test_tracker_basic() {
        let mut t = EmuCoverageTracker::new();
        t.record(0x1000);
        assert!(t.was_visited(0x1000));
        assert!(!t.was_visited(0x2000));
    }
    #[test]
    fn test_tracker_coverage_pct() {
        let mut t = EmuCoverageTracker::new();
        for a in 0x1000u64..0x1010 {
            t.record(a);
        }
        let pct = t.coverage_pct(0x1000, 0x1010);
        assert!((pct - 100.0).abs() < 1e-6);
    }

    // ── IoPortMap ─────────────────────────────────────────────────────────────

    #[test]
    fn test_io_default_read() {
        assert_eq!(IoPortMap::new().read(0x60), 0xFF);
    }
    #[test]
    fn test_io_exact() {
        struct S;
        impl IoPortHandler for S {
            fn read(&self, _: u16) -> u32 {
                42
            }
            fn write(&self, _: u16, _: u32) {}
        }
        let mut m = IoPortMap::new();
        m.register_exact(0x60, Box::new(S));
        assert_eq!(m.read(0x60), 42);
        assert_eq!(m.read(0x61), 0xFF);
    }
    #[test]
    fn test_io_range() {
        struct R;
        impl IoPortHandler for R {
            fn read(&self, p: u16) -> u32 {
                u32::from(p)
            }
            fn write(&self, _: u16, _: u32) {}
        }
        let mut m = IoPortMap::new();
        m.register_range(0x20, 0x21, Box::new(R));
        assert_eq!(m.read(0x20), 0x20);
        assert_eq!(m.read(0x21), 0x21);
        assert_eq!(m.read(0x22), 0xFF);
    }

    // ── MMIO ──────────────────────────────────────────────────────────────────

    #[test]
    fn test_mmio_read() {
        struct CD {
            v: u64,
        }
        impl MmioDevice for CD {
            fn mmio_read(&self, _: u64, _: usize) -> u64 {
                self.v
            }
            fn mmio_write(&mut self, _: u64, _: usize, v: u64) {
                self.v = v;
            }
            fn name(&self) -> &'static str {
                "cd"
            }
        }
        let mut mm = MmioMap::new();
        mm.register(MmioRegion::new(0xF000, 0x100, Box::new(CD { v: 0xABCD })))
            .unwrap();
        assert_eq!(mm.read(0xF000, 4), Some(0xABCD));
        assert_eq!(mm.read(0x1000, 4), None);
    }
    #[test]
    fn test_mmio_overlap_rejected() {
        struct D;
        impl MmioDevice for D {
            fn mmio_read(&self, _: u64, _: usize) -> u64 {
                0
            }
            fn mmio_write(&mut self, _: u64, _: usize, _: u64) {}
            fn name(&self) -> &'static str {
                "d"
            }
        }
        let mut mm = MmioMap::new();
        mm.register(MmioRegion::new(0x1000, 0x100, Box::new(D)))
            .unwrap();
        assert!(
            mm.register(MmioRegion::new(0x1050, 0x100, Box::new(D)))
                .is_err()
        );
    }

    // ── InterruptController ───────────────────────────────────────────────────

    #[test]
    fn test_interrupt_raise_pop() {
        let mut ic = InterruptController::new();
        ic.register_vector(InterruptVector {
            number: 3,
            handler_addr: 0xDEAD,
            description: "BP".into(),
        });
        ic.raise(3);
        let v = ic.next_pending().unwrap();
        assert_eq!(v.number, 3);
        assert!(ic.next_pending().is_none());
    }
    #[test]
    fn test_interrupt_disabled() {
        let mut ic = InterruptController::new();
        ic.disable();
        ic.raise(3);
        assert_eq!(ic.pending_count(), 0);
    }

    // ── Exceptions ────────────────────────────────────────────────────────────

    #[test]
    fn test_exception_vector() {
        assert_eq!(ExceptionKind::PageFault.vector(), 14);
        assert_eq!(ExceptionKind::Unknown(42).vector(), 42);
    }
    #[test]
    fn test_exception_error_code() {
        let e = CpuException::new(ExceptionKind::PageFault, 0xDEAD).with_error_code(0b110);
        assert_eq!(e.error_code, Some(0b110));
    }

    // ── RegisterFile ──────────────────────────────────────────────────────────

    #[test]
    fn test_regfile_rw() {
        let mut rf = RegisterFile::new(vec!["rax".into(), "rbx".into()]);
        rf.write(0, 0xDEAD).unwrap();
        assert_eq!(rf.read(0).unwrap(), 0xDEAD);
    }
    #[test]
    fn test_regfile_index_of() {
        let rf = RegisterFile::new(vec!["RAX".into(), "RBX".into()]);
        assert_eq!(rf.index_of("rax"), Some(0));
        assert_eq!(rf.index_of("xyz"), None);
    }
    #[test]
    fn test_regfile_snapshot() {
        let mut rf = RegisterFile::new(vec!["r0".into(), "r1".into()]);
        rf.write(0, 10).unwrap();
        let s = rf.snapshot();
        rf.zero_all();
        rf.restore(&s).unwrap();
        assert_eq!(rf.read(0).unwrap(), 10);
    }

    // ── FlatMemory ────────────────────────────────────────────────────────────

    #[test]
    fn test_flat_rw() {
        let mut fm = FlatMemory::new(0x1000, 256, MemPerms::ALL);
        fm.write(0x1000, &[1, 2, 3]).unwrap();
        assert_eq!(fm.read(0x1000, 3).unwrap(), [1, 2, 3]);
    }
    #[test]
    fn test_flat_oob() {
        let fm = FlatMemory::new(0x1000, 4, MemPerms::ALL);
        assert!(fm.read(0x1004, 1).is_err());
    }
    #[test]
    fn test_flat_no_write_perm() {
        let mut fm = FlatMemory::new(0x1000, 4, MemPerms::READ | MemPerms::EXEC);
        assert!(fm.write(0x1000, &[0xAA]).is_err());
    }

    // ── InsnTrace ─────────────────────────────────────────────────────────────

    #[test]
    fn test_insn_trace_circular() {
        let mut tr = InsnTrace::new(3);
        for i in 0u64..5 {
            tr.push(TraceEntry {
                pc: i * 4,
                size: 4,
                bytes: vec![],
                disasm: String::new(),
            });
        }
        assert_eq!(tr.len(), 3);
        assert_eq!(tr.last_n(1)[0].pc, 16);
    }

    // ── SnapshotManager ───────────────────────────────────────────────────────

    #[test]
    fn test_snapshot_save_restore() {
        let mut mgr = SnapshotManager::new();
        let mut emu = EmulatorFactory::create(EmulatorArch::X86_64);
        emu.write_register(x86_regs::RAX, 0xBEEF).unwrap();
        let id = mgr.save(emu.as_ref(), "check").unwrap();
        emu.write_register(x86_regs::RAX, 0).unwrap();
        mgr.restore(emu.as_mut(), id).unwrap();
        assert_eq!(emu.read_register(x86_regs::RAX).unwrap(), 0xBEEF);
    }
    #[test]
    fn test_snapshot_remove() {
        let mut mgr = SnapshotManager::new();
        let emu = EmulatorFactory::create(EmulatorArch::X86_64);
        let id = mgr.save(emu.as_ref(), "snap").unwrap();
        mgr.remove(id).unwrap();
        assert_eq!(mgr.count(), 0);
    }

    // ── EmuSession ────────────────────────────────────────────────────────────

    #[test]
    fn test_session_run() {
        let emu = EmulatorFactory::create(EmulatorArch::X86_64);
        let mut s = EmuSession::new(emu, 128);
        s.emulator_mut()
            .map_memory(0x1000, 0x1000, MemPerms::ALL)
            .unwrap();
        s.emulator_mut()
            .write_memory(0x1000, &[0x90, 0x90, 0xF4])
            .unwrap();
        s.run(0x1000, 0x2000, 0, 0).unwrap();
        assert!(s.stats().insns_executed >= 2);
    }

    // ── MemoryDumper ─────────────────────────────────────────────────────────

    #[test]
    fn test_memory_dumper() {
        let mut md = MemoryDumper::new();
        md.record_write(0x1000, vec![0xAA, 0xBB]);
        assert_eq!(md.writes().len(), 1);
        assert_eq!(md.writes()[0].1, [0xAA, 0xBB]);
        md.clear();
        assert!(md.writes().is_empty());
    }

    // ── HookAction / EmuHookManager ──────────────────────────────────────────

    #[test]
    fn test_hook_manager_dispatch() {
        let mut hm = EmuHookManager::new();
        hm.register(0x1000, |_| HookAction::StopEmulation);
        assert_eq!(hm.dispatch(0x1000), HookAction::StopEmulation);
        assert_eq!(hm.dispatch(0x2000), HookAction::Continue);
    }
    #[test]
    fn test_hook_manager_unregister() {
        let mut hm = EmuHookManager::new();
        hm.register(0x1000, |_| HookAction::Continue);
        assert_eq!(hm.unregister(0x1000), 1);
        assert_eq!(hm.hook_site_count(), 0);
    }

    // ── EmulatorRegistry ─────────────────────────────────────────────────────

    #[test]
    fn test_registry_empty() {
        let r = EmulatorRegistry::new();
        assert_eq!(r.names().len(), 0);
        assert!(r.create(EmulatorArch::X86_64).is_none());
    }

    // ── NullDevice ───────────────────────────────────────────────────────────

    #[test]
    fn test_null_device() {
        let mut d = NullDevice::new("null");
        assert_eq!(d.name(), "null");
        d.reset();
        d.tick(1000);
        assert!(!d.irq_pending());
        assert!(d.irq_vector().is_none());
    }

    // ── SnapshotId ───────────────────────────────────────────────────────────

    #[test]
    fn test_snapshot_id() {
        assert_ne!(SnapshotId(1), SnapshotId(2));
    }

    // ── EmulatorError ────────────────────────────────────────────────────────

    #[test]
    fn test_error_display() {
        let e = EmulatorError::MemFault {
            addr: 0x1234,
            op: "read".into(),
        };
        assert!(e.to_string().contains("0x0000000000001234"));
    }

    // ── EmuCheckpointManager ─────────────────────────────────────────────────

    #[test]
    fn test_checkpoint_save_restore() {
        let mut cm = EmuCheckpointManager::new();
        let mut emu = EmulatorFactory::create(EmulatorArch::X86_64);
        emu.map_memory(0x1000, 0x100, MemPerms::ALL).unwrap();
        emu.write_register(x86_regs::RAX, 0xCAFE).unwrap();
        let id = cm.save_checkpoint(emu.as_ref()).unwrap();
        emu.write_register(x86_regs::RAX, 0).unwrap();
        assert!(cm.restore_checkpoint(id, emu.as_mut()).unwrap());
        assert_eq!(emu.read_register(x86_regs::RAX).unwrap(), 0xCAFE);
    }
    #[test]
    fn test_checkpoint_delete() {
        let mut cm = EmuCheckpointManager::new();
        let emu = EmulatorFactory::create(EmulatorArch::X86_64);
        let id = cm.save_checkpoint(emu.as_ref()).unwrap();
        assert!(cm.delete_checkpoint(id));
        assert_eq!(cm.checkpoint_count(), 0);
    }
}
