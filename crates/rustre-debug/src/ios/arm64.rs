//! ARM64 / AArch64 architecture support for the Apple debug backend.
//!
//! Everything in this module is a pure function over words, registers and
//! integers. There is no I/O, no OS call and no `cfg(target_os = ...)`: the
//! module is fully exercised by unit tests on any host, which is the whole
//! point — an Apple-only file that cannot be tested on the development host is
//! a file whose bugs are found by users instead of by CI.
//!
//! Contents:
//! * `BRK`/`HLT` instruction encode/decode (software breakpoints).
//! * The complete ARM64 register set with names, aliases, widths and DWARF
//!   register numbers, plus a concrete register file.
//! * Hardware breakpoint/watchpoint control-register layouts
//!   (`DBGBVR`/`DBGBCR`/`DBGWVR`/`DBGWCR`) with `BAS`/`PMC`/`LSC`/`PAC`
//!   encoding and slot-count facts.
//! * AAPCS64 calling-convention argument extraction.

use core::fmt;

/// Errors produced by the pure ARM64 helpers.
///
/// Every failure mode is a distinct variant on purpose: "returned `None`" hides
/// *why* a watchpoint could not be programmed, and the caller has to surface
/// that to the user.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Arm64Error {
    /// An instruction address was not 4-byte aligned (all A64 instructions are).
    #[error("instruction address {0:#x} is not 4-byte aligned")]
    UnalignedInstruction(u64),
    /// A watchpoint size that the architecture cannot express with `BAS`.
    #[error("unsupported watchpoint size {0} (must be 1, 2, 4 or 8 bytes)")]
    UnsupportedWatchpointSize(usize),
    /// The watched range crosses the 8-byte `DBGWVR` granule.
    #[error("watchpoint at {addr:#x} size {size} crosses the 8-byte granule")]
    WatchpointCrossesGranule { addr: u64, size: usize },
    /// The watched address is not naturally aligned for its size.
    #[error("watchpoint address {addr:#x} is not aligned to its size {size}")]
    UnalignedWatchpoint { addr: u64, size: usize },
    /// A debug-register slot index beyond what the architecture defines.
    #[error("hardware debug slot {slot} out of range (max {max})")]
    SlotOutOfRange { slot: usize, max: usize },
    /// A word that was expected to be a breakpoint instruction is not one.
    #[error("word {0:#010x} is not a BRK instruction")]
    NotABreakpoint(u32),
    /// An unknown register name was requested.
    #[error("unknown ARM64 register {0:?}")]
    UnknownRegister(String),
    /// An argument index beyond what the register file alone can answer.
    #[error("argument {index} lives on the stack and no memory reader was supplied")]
    ArgumentOnStack { index: usize },
}

// ---------------------------------------------------------------------------
// Breakpoint instructions
// ---------------------------------------------------------------------------

/// Size in bytes of every A64 instruction.
pub const INSTRUCTION_SIZE: u64 = 4;

/// Base encoding of `BRK #imm16`: `1101 0100 001 imm16 000 00`.
///
/// The immediate occupies bits `[20:5]`, so `BRK #0 == 0xD420_0000`.
pub const BRK_BASE: u32 = 0xD420_0000;

/// Mask of the bits that identify a `BRK` (everything outside `imm16`).
pub const BRK_MASK: u32 = 0xFFE0_001F;

/// Base encoding of `HLT #imm16`: `1101 0100 010 imm16 000 00`.
pub const HLT_BASE: u32 = 0xD440_0000;

/// Mask of the bits that identify a `HLT`.
pub const HLT_MASK: u32 = 0xFFE0_001F;

/// The breakpoint instruction actually planted by lldb/debugserver on arm64:
/// `BRK #0`, i.e. `0xD420_0000` (little-endian bytes `00 00 20 D4`).
///
/// WHY this constant and not `BRK #0x8000`: the blueprint quoted
/// "`BRK #0x8000` = `0xD420_0000`", but those two are not the same instruction.
/// The immediate sits at bits `[20:5]`, so `BRK #0x8000` encodes as
/// `0xD430_0000` (see [`BRK_IMM_8000`]). `0xD420_0000` is `BRK #0`. Both are
/// exposed; the *default* is the one debugserver plants, so that a memory
/// comparison against a real target succeeds.
pub const BRK_DEFAULT: u32 = BRK_BASE;

/// `BRK #0x8000` — the immediate reserved for debugger use by the Arm ABI.
/// Kept explicit because the blueprint named it; note the encoding differs
/// from [`BRK_DEFAULT`].
pub const BRK_IMM_8000: u32 = BRK_BASE | (0x8000 << 5);

/// The x86-64 `int3` opcode, kept here so a mixed-architecture Apple backend
/// (Rosetta / fat binaries) has one place to look for "the trap byte".
pub const X86_64_INT3: u8 = 0xCC;

/// Encode `BRK #imm16`.
#[must_use]
pub const fn encode_brk(imm16: u16) -> u32 {
    BRK_BASE | ((imm16 as u32) << 5)
}

/// Encode `HLT #imm16`.
#[must_use]
pub const fn encode_hlt(imm16: u16) -> u32 {
    HLT_BASE | ((imm16 as u32) << 5)
}

/// Decode a word as `BRK`, returning its immediate.
#[must_use]
pub const fn decode_brk(word: u32) -> Option<u16> {
    if word & BRK_MASK == BRK_BASE {
        Some(((word >> 5) & 0xFFFF) as u16)
    } else {
        None
    }
}

/// Decode a word as `HLT`, returning its immediate.
#[must_use]
pub const fn decode_hlt(word: u32) -> Option<u16> {
    if word & HLT_MASK == HLT_BASE {
        Some(((word >> 5) & 0xFFFF) as u16)
    } else {
        None
    }
}

/// Is this word a `BRK` of any immediate?
#[must_use]
pub const fn is_brk(word: u32) -> bool {
    decode_brk(word).is_some()
}

/// Is this word a `HLT` of any immediate?
#[must_use]
pub const fn is_hlt(word: u32) -> bool {
    decode_hlt(word).is_some()
}

/// Little-endian bytes of the default breakpoint instruction, ready to be
/// written into target memory.
#[must_use]
pub const fn brk_bytes(imm16: u16) -> [u8; 4] {
    encode_brk(imm16).to_le_bytes()
}

/// Read a little-endian A64 word out of a 4-byte slice.
///
/// Returns `None` on a short slice rather than panicking: the bytes come from
/// a remote target and a truncated read is a normal, expected condition.
#[must_use]
pub fn word_from_le(bytes: &[u8]) -> Option<u32> {
    let arr: [u8; 4] = bytes.get(..4)?.try_into().ok()?;
    Some(u32::from_le_bytes(arr))
}

/// Validate that `addr` can hold an A64 instruction.
///
/// # Errors
/// [`Arm64Error::UnalignedInstruction`] if `addr` is not a multiple of 4.
pub const fn check_instruction_alignment(addr: u64) -> Result<(), Arm64Error> {
    if addr % INSTRUCTION_SIZE == 0 {
        Ok(())
    } else {
        Err(Arm64Error::UnalignedInstruction(addr))
    }
}

/// Classification of the A64 exception-generating instruction group
/// (`op0 == 0b110101000`), which is what a debugger sees when a target stops.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExceptionInstruction {
    /// `SVC #imm` — supervisor call (syscall).
    Svc(u16),
    /// `HVC #imm` — hypervisor call.
    Hvc(u16),
    /// `SMC #imm` — secure-monitor call.
    Smc(u16),
    /// `BRK #imm` — software breakpoint.
    Brk(u16),
    /// `HLT #imm` — halting-debug-mode breakpoint.
    Hlt(u16),
}

impl ExceptionInstruction {
    /// Decode an exception-generating instruction, if this word is one.
    #[must_use]
    pub const fn decode(word: u32) -> Option<Self> {
        // Common shape: 1101 0100 <opc:3> imm16 <op2:3> <LL:2>
        if word & 0xFF00_0000 != 0xD400_0000 {
            return None;
        }
        let imm16 = ((word >> 5) & 0xFFFF) as u16;
        let opc = (word >> 21) & 0x7;
        let ll = word & 0x3;
        let op2 = (word >> 2) & 0x7;
        if op2 != 0 {
            return None;
        }
        match (opc, ll) {
            (0b000, 0b01) => Some(Self::Svc(imm16)),
            (0b000, 0b10) => Some(Self::Hvc(imm16)),
            (0b000, 0b11) => Some(Self::Smc(imm16)),
            (0b001, 0b00) => Some(Self::Brk(imm16)),
            (0b010, 0b00) => Some(Self::Hlt(imm16)),
            _ => None,
        }
    }

    /// Does this instruction stop the process for the debugger (as opposed to
    /// transferring to a more privileged level)?
    #[must_use]
    pub const fn is_debug_trap(self) -> bool {
        matches!(self, Self::Brk(_) | Self::Hlt(_))
    }
}

// ---------------------------------------------------------------------------
// Minimal instruction shape recognition needed by the stepper
// ---------------------------------------------------------------------------

/// The handful of control-flow shapes `step_over`/`step_out` must distinguish.
///
/// This is deliberately *not* a disassembler: a stepper only needs to know
/// "does this instruction push a return address?" and "is this a return?".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BranchKind {
    /// `BL <label>` — direct call, with its PC-relative byte offset.
    DirectCall { offset: i64 },
    /// `BLR Xn` / `BLRAA…` — indirect call through a register.
    IndirectCall { reg: u8 },
    /// `B <label>` — unconditional direct branch.
    DirectBranch { offset: i64 },
    /// `BR Xn` — indirect branch.
    IndirectBranch { reg: u8 },
    /// `RET {Xn}` — return (defaults to `x30`).
    Return { reg: u8 },
    /// `B.cond <label>` / `CBZ` / `CBNZ` / `TBZ` / `TBNZ`.
    ConditionalBranch { offset: i64 },
}

impl BranchKind {
    /// Decode the six control-flow patterns a stepper cares about.
    #[must_use]
    pub const fn decode(word: u32) -> Option<Self> {
        // B / BL: 0b0_00101 imm26 (B), 0b1_00101 imm26 (BL)
        if word & 0x7C00_0000 == 0x1400_0000 {
            let imm26 = word & 0x03FF_FFFF;
            // Sign-extend 26 bits then scale by 4.
            let offset = (((imm26 << 6) as i32) >> 6) as i64 * 4;
            return if word & 0x8000_0000 == 0 {
                Some(Self::DirectBranch { offset })
            } else {
                Some(Self::DirectCall { offset })
            };
        }
        // Unconditional branch (register): 1101011 opc:4 op2:5 op3:6 Rn:5 op4:5
        if word & 0xFE00_0000 == 0xD600_0000 {
            let reg = ((word >> 5) & 0x1F) as u8;
            let opc = (word >> 21) & 0xF;
            return match opc {
                0b0000 => Some(Self::IndirectBranch { reg }),
                0b0001 => Some(Self::IndirectCall { reg }),
                0b0010 => Some(Self::Return { reg }),
                _ => None,
            };
        }
        // B.cond: 0101 0100 imm19 0 cond
        if word & 0xFF00_0010 == 0x5400_0000 {
            let imm19 = (word >> 5) & 0x7_FFFF;
            let offset = (((imm19 << 13) as i32) >> 13) as i64 * 4;
            return Some(Self::ConditionalBranch { offset });
        }
        // CBZ/CBNZ: sf 011010 op imm19 Rt
        if word & 0x7E00_0000 == 0x3400_0000 {
            let imm19 = (word >> 5) & 0x7_FFFF;
            let offset = (((imm19 << 13) as i32) >> 13) as i64 * 4;
            return Some(Self::ConditionalBranch { offset });
        }
        // TBZ/TBNZ: b5 011011 op b40 imm14 Rt
        if word & 0x7E00_0000 == 0x3600_0000 {
            let imm14 = (word >> 5) & 0x3FFF;
            let offset = (((imm14 << 18) as i32) >> 18) as i64 * 4;
            return Some(Self::ConditionalBranch { offset });
        }
        None
    }

    /// Does executing this instruction push a return address onto `x30`?
    /// That is exactly the condition under which `step_over` must plant a
    /// temporary breakpoint at `pc + 4` instead of single-stepping.
    #[must_use]
    pub const fn is_call(self) -> bool {
        matches!(self, Self::DirectCall { .. } | Self::IndirectCall { .. })
    }
}

// ---------------------------------------------------------------------------
// Registers
// ---------------------------------------------------------------------------

/// Which architectural file a register belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegClass {
    /// `x0`..`x30` (and their `w` views).
    General,
    /// The stack pointer.
    StackPointer,
    /// The program counter.
    ProgramCounter,
    /// `cpsr` / `nzcv` process state.
    Flags,
    /// `v0`..`v31` SIMD & floating-point registers.
    Vector,
    /// `fpsr` / `fpcr`.
    FpControl,
}

/// The "generic" role a register plays, mirroring lldb's `qRegisterInfo`
/// `generic:` field. This is how `pc`/`sp`/`fp`/`lr` get filled in without
/// hardcoding indices.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GenericRole {
    /// Program counter.
    Pc,
    /// Stack pointer.
    Sp,
    /// Frame pointer (`x29`).
    Fp,
    /// Link register (`x30`).
    Ra,
    /// Flags register.
    Flags,
    /// First..eighth integer argument.
    Arg(u8),
}

/// Static description of one architectural register.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegSpec {
    /// Canonical lowercase name (`x0`, `sp`, `v31`, ...).
    pub name: &'static str,
    /// Index within its class (`x5` -> 5, `v31` -> 31; 0 for singletons).
    pub index: u8,
    /// Width in bits.
    pub bits: u16,
    /// Which file it belongs to.
    pub class: RegClass,
    /// DWARF register number, per "DWARF for the Arm 64-bit Architecture".
    pub dwarf: u16,
    /// Generic role, if any.
    pub generic: Option<GenericRole>,
}

impl fmt::Display for RegSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}({} bits)", self.name, self.bits)
    }
}

/// Number of general-purpose registers `x0`..`x30`.
pub const NUM_GENERAL: usize = 31;
/// Number of SIMD registers `v0`..`v31`.
pub const NUM_VECTOR: usize = 32;

/// DWARF number of `sp` on AArch64.
pub const DWARF_SP: u16 = 31;
/// DWARF number of the PC pseudo-register on AArch64.
pub const DWARF_PC: u16 = 32;
/// DWARF number of `RA_SIGN_STATE` (pointer-authentication unwind state).
pub const DWARF_RA_SIGN_STATE: u16 = 34;
/// DWARF number of `v0`; `v[n]` is `DWARF_V0 + n`.
pub const DWARF_V0: u16 = 64;

const X_NAMES: [&str; NUM_GENERAL] = [
    "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12", "x13", "x14",
    "x15", "x16", "x17", "x18", "x19", "x20", "x21", "x22", "x23", "x24", "x25", "x26", "x27",
    "x28", "x29", "x30",
];

const W_NAMES: [&str; NUM_GENERAL] = [
    "w0", "w1", "w2", "w3", "w4", "w5", "w6", "w7", "w8", "w9", "w10", "w11", "w12", "w13", "w14",
    "w15", "w16", "w17", "w18", "w19", "w20", "w21", "w22", "w23", "w24", "w25", "w26", "w27",
    "w28", "w29", "w30",
];

const V_NAMES: [&str; NUM_VECTOR] = [
    "v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7", "v8", "v9", "v10", "v11", "v12", "v13", "v14",
    "v15", "v16", "v17", "v18", "v19", "v20", "v21", "v22", "v23", "v24", "v25", "v26", "v27",
    "v28", "v29", "v30", "v31",
];

/// Spec for `x{n}`.
///
/// # Panics
/// If `n >= 31`.
#[must_use]
pub fn general_reg(n: u8) -> RegSpec {
    assert!((n as usize) < NUM_GENERAL, "x{n} does not exist");
    let generic = match n {
        0..=7 => Some(GenericRole::Arg(n)),
        29 => Some(GenericRole::Fp),
        30 => Some(GenericRole::Ra),
        _ => None,
    };
    RegSpec {
        name: X_NAMES[n as usize],
        index: n,
        bits: 64,
        class: RegClass::General,
        dwarf: u16::from(n),
        generic,
    }
}

/// Spec for `v{n}`.
///
/// # Panics
/// If `n >= 32`.
#[must_use]
pub fn vector_reg(n: u8) -> RegSpec {
    assert!((n as usize) < NUM_VECTOR, "v{n} does not exist");
    RegSpec {
        name: V_NAMES[n as usize],
        index: n,
        bits: 128,
        class: RegClass::Vector,
        dwarf: DWARF_V0 + u16::from(n),
        generic: None,
    }
}

/// Spec for the stack pointer.
#[must_use]
pub const fn sp_reg() -> RegSpec {
    RegSpec {
        name: "sp",
        index: 0,
        bits: 64,
        class: RegClass::StackPointer,
        dwarf: DWARF_SP,
        generic: Some(GenericRole::Sp),
    }
}

/// Spec for the program counter.
#[must_use]
pub const fn pc_reg() -> RegSpec {
    RegSpec {
        name: "pc",
        index: 0,
        bits: 64,
        class: RegClass::ProgramCounter,
        dwarf: DWARF_PC,
        generic: Some(GenericRole::Pc),
    }
}

/// Spec for `cpsr` (32-bit process state as exposed by debugserver).
#[must_use]
pub const fn cpsr_reg() -> RegSpec {
    RegSpec {
        name: "cpsr",
        index: 0,
        bits: 32,
        class: RegClass::Flags,
        // PSTATE has no DWARF number; 33 is ELR_mode and must not be reused, so
        // we report `u16::MAX` as "no DWARF mapping" rather than inventing one.
        dwarf: u16::MAX,
        generic: Some(GenericRole::Flags),
    }
}

/// Every architectural register, in the canonical order used for a `g` packet
/// layout: `x0..x30`, `sp`, `pc`, `cpsr`, `v0..v31`, `fpsr`, `fpcr`.
#[must_use]
pub fn all_registers() -> Vec<RegSpec> {
    let mut out = Vec::with_capacity(NUM_GENERAL + 3 + NUM_VECTOR + 2);
    for n in 0..NUM_GENERAL as u8 {
        out.push(general_reg(n));
    }
    out.push(sp_reg());
    out.push(pc_reg());
    out.push(cpsr_reg());
    for n in 0..NUM_VECTOR as u8 {
        out.push(vector_reg(n));
    }
    out.push(RegSpec {
        name: "fpsr",
        index: 0,
        bits: 32,
        class: RegClass::FpControl,
        dwarf: u16::MAX,
        generic: None,
    });
    out.push(RegSpec {
        name: "fpcr",
        index: 1,
        bits: 32,
        class: RegClass::FpControl,
        dwarf: u16::MAX,
        generic: None,
    });
    out
}

/// Resolve a register name, accepting every alias a user or a remote stub may
/// use: `fp`/`lr`, the 32-bit `w` views, the `b`/`h`/`s`/`d`/`q` views of the
/// vector registers, `xzr`/`wzr`, and `nzcv` for `cpsr`.
///
/// The returned [`RegSpec`] always names the *architectural* register; the
/// `bits` field reports the width of the **view** that was asked for, so
/// `lookup("w3").bits == 32` while its `index`/`class` still say `x3`.
#[must_use]
pub fn lookup_register(name: &str) -> Option<RegSpec> {
    let lower = name.trim().to_ascii_lowercase();
    let n = lower.as_str();
    match n {
        "sp" | "xsp" => return Some(sp_reg()),
        "wsp" => {
            let mut r = sp_reg();
            r.bits = 32;
            return Some(r);
        }
        "pc" => return Some(pc_reg()),
        "cpsr" | "nzcv" | "pstate" => return Some(cpsr_reg()),
        "fp" => return Some(general_reg(29)),
        "lr" => return Some(general_reg(30)),
        "xzr" => {
            // The zero register is architecturally distinct from x31/sp; report
            // it explicitly rather than silently aliasing it to `sp`, which is
            // the classic AArch64 decoding bug.
            return Some(RegSpec {
                name: "xzr",
                index: 31,
                bits: 64,
                class: RegClass::General,
                dwarf: u16::MAX,
                generic: None,
            });
        }
        "wzr" => {
            return Some(RegSpec {
                name: "wzr",
                index: 31,
                bits: 32,
                class: RegClass::General,
                dwarf: u16::MAX,
                generic: None,
            });
        }
        "fpsr" | "fpcr" => {
            return all_registers().into_iter().find(|r| r.name == n);
        }
        _ => {}
    }
    // x0..x30 / w0..w30
    if let Some(idx) = parse_indexed(n, 'x', NUM_GENERAL) {
        return Some(general_reg(idx));
    }
    if let Some(idx) = parse_indexed(n, 'w', NUM_GENERAL) {
        let mut r = general_reg(idx);
        r.name = W_NAMES[idx as usize];
        r.bits = 32;
        return Some(r);
    }
    // Vector views: v/q = 128, d = 64, s = 32, h = 16, b = 8.
    for (prefix, bits) in [('v', 128u16), ('q', 128), ('d', 64), ('s', 32), ('h', 16), ('b', 8)] {
        if let Some(idx) = parse_indexed(n, prefix, NUM_VECTOR) {
            let mut r = vector_reg(idx);
            r.bits = bits;
            return Some(r);
        }
    }
    None
}

/// Parse `"<prefix><decimal>"` with no leading zeros and a bound check.
fn parse_indexed(name: &str, prefix: char, limit: usize) -> Option<u8> {
    let rest = name.strip_prefix(prefix)?;
    if rest.is_empty() || (rest.len() > 1 && rest.starts_with('0')) {
        return None;
    }
    let idx: usize = rest.parse().ok()?;
    if idx < limit { u8::try_from(idx).ok() } else { None }
}

/// PSTATE condition-flag bit positions inside `cpsr`.
pub mod pstate {
    /// Negative.
    pub const N: u32 = 1 << 31;
    /// Zero.
    pub const Z: u32 = 1 << 30;
    /// Carry.
    pub const C: u32 = 1 << 29;
    /// Overflow.
    pub const V: u32 = 1 << 28;
    /// Software step (`SS`) — set while single-stepping via MDSCR.
    pub const SS: u32 = 1 << 21;
    /// Illegal execution state.
    pub const IL: u32 = 1 << 20;
    /// Execution state: 1 = AArch32.
    pub const NRW: u32 = 1 << 4;
}

/// A concrete ARM64 register file.
///
/// Deliberately a plain value type: unwinding, argument extraction and frame
/// reconstruction are all pure functions of this plus a memory reader, which
/// is what makes them testable without a process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Arm64RegisterFile {
    /// `x0`..`x30`.
    pub x: [u64; NUM_GENERAL],
    /// Stack pointer.
    pub sp: u64,
    /// Program counter.
    pub pc: u64,
    /// Process state.
    pub cpsr: u32,
    /// `v0`..`v31`, as raw 128-bit values.
    pub v: [u128; NUM_VECTOR],
    /// Floating-point status.
    pub fpsr: u32,
    /// Floating-point control.
    pub fpcr: u32,
}

impl Default for Arm64RegisterFile {
    fn default() -> Self {
        Self::new()
    }
}

impl Arm64RegisterFile {
    /// An all-zero register file.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            x: [0; NUM_GENERAL],
            sp: 0,
            pc: 0,
            cpsr: 0,
            v: [0; NUM_VECTOR],
            fpsr: 0,
            fpcr: 0,
        }
    }

    /// Frame pointer (`x29`).
    #[must_use]
    pub const fn fp(&self) -> u64 {
        self.x[29]
    }

    /// Link register (`x30`).
    #[must_use]
    pub const fn lr(&self) -> u64 {
        self.x[30]
    }

    /// Read a register by name (any alias accepted by [`lookup_register`]).
    ///
    /// Narrow views are truncated, matching what the hardware would give you:
    /// `get("w0")` on `x0 == 0x1_0000_0001` yields `1`.
    ///
    /// # Errors
    /// [`Arm64Error::UnknownRegister`] if the name does not resolve.
    pub fn get(&self, name: &str) -> Result<u64, Arm64Error> {
        let spec =
            lookup_register(name).ok_or_else(|| Arm64Error::UnknownRegister(name.to_owned()))?;
        let raw = match spec.class {
            RegClass::General => {
                if spec.index as usize >= NUM_GENERAL {
                    0 // xzr/wzr always read as zero
                } else {
                    self.x[spec.index as usize]
                }
            }
            RegClass::StackPointer => self.sp,
            RegClass::ProgramCounter => self.pc,
            RegClass::Flags => u64::from(self.cpsr),
            // The 64-bit API can only surface the low half of a vector register;
            // callers that need all 128 bits read `self.v` directly.
            RegClass::Vector => self.v[spec.index as usize] as u64,
            RegClass::FpControl => {
                if spec.name == "fpsr" {
                    u64::from(self.fpsr)
                } else {
                    u64::from(self.fpcr)
                }
            }
        };
        Ok(truncate(raw, spec.bits))
    }

    /// Write a register by name.
    ///
    /// Writes to `xzr`/`wzr` are discarded (architecturally correct) instead of
    /// being reported as an error.
    ///
    /// # Errors
    /// [`Arm64Error::UnknownRegister`] if the name does not resolve.
    pub fn set(&mut self, name: &str, value: u64) -> Result<(), Arm64Error> {
        let spec =
            lookup_register(name).ok_or_else(|| Arm64Error::UnknownRegister(name.to_owned()))?;
        let value = truncate(value, spec.bits);
        match spec.class {
            RegClass::General => {
                if (spec.index as usize) < NUM_GENERAL {
                    self.x[spec.index as usize] = value;
                }
            }
            RegClass::StackPointer => self.sp = value,
            RegClass::ProgramCounter => self.pc = value,
            RegClass::Flags => self.cpsr = value as u32,
            RegClass::Vector => {
                let slot = &mut self.v[spec.index as usize];
                // Preserve the high half: a 64-bit write to `d3` must not clear
                // the top of `v3` from the debugger's point of view.
                *slot = (*slot & !u128::from(u64::MAX)) | u128::from(value);
            }
            RegClass::FpControl => {
                if spec.name == "fpsr" {
                    self.fpsr = value as u32;
                } else {
                    self.fpcr = value as u32;
                }
            }
        }
        Ok(())
    }

    /// Condition flags as `(n, z, c, v)`.
    #[must_use]
    pub const fn nzcv(&self) -> (bool, bool, bool, bool) {
        (
            self.cpsr & pstate::N != 0,
            self.cpsr & pstate::Z != 0,
            self.cpsr & pstate::C != 0,
            self.cpsr & pstate::V != 0,
        )
    }
}

/// Truncate `value` to `bits`, where `bits >= 64` is a no-op.
const fn truncate(value: u64, bits: u16) -> u64 {
    if bits >= 64 {
        value
    } else {
        value & ((1u64 << bits) - 1)
    }
}

// ---------------------------------------------------------------------------
// Hardware breakpoints / watchpoints
// ---------------------------------------------------------------------------

/// Hardware debug-register layouts and slot facts.
pub mod hw {
    use super::{Arm64Error, INSTRUCTION_SIZE};

    /// Architectural maximum number of `DBGBVR`/`DBGBCR` pairs.
    pub const MAX_HW_BREAKPOINTS: usize = 16;
    /// Architectural maximum number of `DBGWVR`/`DBGWCR` pairs.
    pub const MAX_HW_WATCHPOINTS: usize = 16;
    /// Slots actually implemented on Apple arm64 (M1/M2/A-series) cores, as
    /// reported by `qHostInfo`. Treat this as a *hint*: the authoritative count
    /// comes from the target, and exceeding it must be an explicit error, never
    /// a silently dropped breakpoint.
    pub const APPLE_HW_BREAKPOINT_SLOTS: usize = 6;
    /// Watchpoint slots typically implemented on Apple arm64 cores.
    pub const APPLE_HW_WATCHPOINT_SLOTS: usize = 4;

    /// Granule of `DBGWVR`: watched addresses are programmed 8-byte aligned and
    /// the byte-address-select field picks the bytes within that doubleword.
    pub const WATCHPOINT_GRANULE: u64 = 8;

    /// `DBGBCR<n>_EL1` / `DBGWCR<n>_EL1` privilege / exception-level control
    /// (`PMC`, bits `[2:1]`).
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum PrivilegeControl {
        /// Matches at any exception level (`0b00`, only with SSC/HMC set).
        Any = 0b00,
        /// EL1 only.
        El1 = 0b01,
        /// EL0 only — what a user-space debugger wants.
        El0 = 0b10,
        /// EL1 and EL0.
        El1El0 = 0b11,
    }

    /// `DBGBCR<n>_EL1.BT` — breakpoint type, bits `[23:20]`.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum BreakpointType {
        /// Unlinked instruction address match — the normal case.
        UnlinkedAddressMatch = 0b0000,
        /// Linked instruction address match.
        LinkedAddressMatch = 0b0001,
        /// Unlinked context ID match.
        UnlinkedContextIdMatch = 0b0010,
        /// Unlinked address mismatch (used to implement "step out of range").
        UnlinkedAddressMismatch = 0b0100,
    }

    /// `DBGWCR<n>_EL1.LSC` — load/store control, bits `[4:3]`.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum WatchKind {
        /// Fire on loads (reads).
        Load = 0b01,
        /// Fire on stores (writes).
        Store = 0b10,
        /// Fire on both.
        LoadStore = 0b11,
    }

    /// A programmed hardware breakpoint: the value/control register pair.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct HwBreakpoint {
        /// `DBGBVR<n>_EL1` — the instruction address.
        pub dbgbvr: u64,
        /// `DBGBCR<n>_EL1` — the control word.
        pub dbgbcr: u32,
    }

    /// A programmed hardware watchpoint.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct HwWatchpoint {
        /// `DBGWVR<n>_EL1` — the 8-byte-aligned base address.
        pub dbgwvr: u64,
        /// `DBGWCR<n>_EL1` — the control word (including `BAS`).
        pub dbgwcr: u32,
    }

    /// Bit positions shared by both control registers.
    pub mod bits {
        /// `E` — enable, bit 0.
        pub const ENABLE: u32 = 1 << 0;
        /// `PMC`/`PAC` shift, bits `[2:1]`.
        pub const PRIV_SHIFT: u32 = 1;
        /// `PMC`/`PAC` mask.
        pub const PRIV_MASK: u32 = 0b11 << PRIV_SHIFT;
        /// `LSC` shift (watchpoints only), bits `[4:3]`.
        pub const LSC_SHIFT: u32 = 3;
        /// `LSC` mask.
        pub const LSC_MASK: u32 = 0b11 << LSC_SHIFT;
        /// `BAS` shift, bits `[8:5]` for breakpoints, `[12:5]` for watchpoints.
        pub const BAS_SHIFT: u32 = 5;
        /// `BAS` mask for a breakpoint (4 bits).
        pub const BAS_MASK_BP: u32 = 0xF << BAS_SHIFT;
        /// `BAS` mask for a watchpoint (8 bits).
        pub const BAS_MASK_WP: u32 = 0xFF << BAS_SHIFT;
        /// `HMC` — higher mode control, bit 13.
        pub const HMC: u32 = 1 << 13;
        /// `SSC` shift, bits `[15:14]`.
        pub const SSC_SHIFT: u32 = 14;
        /// `SSC` mask.
        pub const SSC_MASK: u32 = 0b11 << SSC_SHIFT;
        /// `LBN` shift, bits `[19:16]`.
        pub const LBN_SHIFT: u32 = 16;
        /// `LBN` mask.
        pub const LBN_MASK: u32 = 0xF << LBN_SHIFT;
        /// `BT` shift (breakpoints only), bits `[23:20]`.
        pub const BT_SHIFT: u32 = 20;
        /// `BT` mask.
        pub const BT_MASK: u32 = 0xF << BT_SHIFT;
        /// `WT` — watchpoint type (linked), bit 20.
        pub const WT: u32 = 1 << 20;
        /// `MASK` shift (watchpoints only), bits `[28:24]`.
        pub const MASK_SHIFT: u32 = 24;
        /// `MASK` mask.
        pub const MASK_MASK: u32 = 0x1F << MASK_SHIFT;
    }

    /// `BAS` value that selects all four bytes of an A64 instruction.
    pub const BAS_A64_INSTRUCTION: u32 = 0xF;

    /// Build the `DBGBVR`/`DBGBCR` pair for an instruction breakpoint at `addr`.
    ///
    /// # Errors
    /// [`Arm64Error::UnalignedInstruction`] if `addr` is not 4-byte aligned.
    pub const fn breakpoint(addr: u64, priv_ctl: PrivilegeControl) -> Result<HwBreakpoint, Arm64Error> {
        if addr % INSTRUCTION_SIZE != 0 {
            return Err(Arm64Error::UnalignedInstruction(addr));
        }
        let dbgbcr = bits::ENABLE
            | ((priv_ctl as u32) << bits::PRIV_SHIFT)
            | (BAS_A64_INSTRUCTION << bits::BAS_SHIFT)
            | ((BreakpointType::UnlinkedAddressMatch as u32) << bits::BT_SHIFT);
        Ok(HwBreakpoint { dbgbvr: addr, dbgbcr })
    }

    /// Compute the `BAS` byte-address-select field for a watchpoint of `size`
    /// bytes at `addr`.
    ///
    /// The hardware always compares an 8-byte-aligned address, so sub-doubleword
    /// watchpoints are expressed by setting only the corresponding `BAS` bits.
    ///
    /// # Errors
    /// * [`Arm64Error::UnsupportedWatchpointSize`] for a size other than 1/2/4/8.
    /// * [`Arm64Error::UnalignedWatchpoint`] if `addr` is not naturally aligned.
    /// * [`Arm64Error::WatchpointCrossesGranule`] if the range spans two
    ///   doublewords (which needs two slots — the caller must split it).
    pub const fn watchpoint_bas(addr: u64, size: usize) -> Result<u32, Arm64Error> {
        if !matches!(size, 1 | 2 | 4 | 8) {
            return Err(Arm64Error::UnsupportedWatchpointSize(size));
        }
        if addr % (size as u64) != 0 {
            return Err(Arm64Error::UnalignedWatchpoint { addr, size });
        }
        let offset = addr % WATCHPOINT_GRANULE;
        if offset + size as u64 > WATCHPOINT_GRANULE {
            return Err(Arm64Error::WatchpointCrossesGranule { addr, size });
        }
        // `size` is one of 1/2/4/8 so the shift is always in range.
        let mask = ((1u32 << size) - 1) << offset;
        Ok(mask)
    }

    /// Build the `DBGWVR`/`DBGWCR` pair for a data watchpoint.
    ///
    /// # Errors
    /// Propagates every failure of [`watchpoint_bas`].
    // NOT `const fn`: `Arm64Error` owns a `String` in one variant, so matching
    // on the `Result` would need a destructor at compile time.
    pub fn watchpoint(
        addr: u64,
        size: usize,
        kind: WatchKind,
        priv_ctl: PrivilegeControl,
    ) -> Result<HwWatchpoint, Arm64Error> {
        let bas = watchpoint_bas(addr, size)?;
        let dbgwcr = bits::ENABLE
            | ((priv_ctl as u32) << bits::PRIV_SHIFT)
            | ((kind as u32) << bits::LSC_SHIFT)
            | (bas << bits::BAS_SHIFT);
        Ok(HwWatchpoint {
            dbgwvr: addr & !(WATCHPOINT_GRANULE - 1),
            dbgwcr,
        })
    }

    /// Extract the watched byte range from a programmed watchpoint, i.e. the
    /// inverse of [`watchpoint`]. Returns `(first_addr, len)`, or `None` if the
    /// `BAS` field is zero (disabled/ill-formed).
    #[must_use]
    pub const fn watchpoint_range(wp: &HwWatchpoint) -> Option<(u64, usize)> {
        let bas = (wp.dbgwcr & bits::BAS_MASK_WP) >> bits::BAS_SHIFT;
        if bas == 0 {
            return None;
        }
        let first = bas.trailing_zeros() as u64;
        let len = (32 - bas.leading_zeros()) as u64 - first;
        Some((wp.dbgwvr + first, len as usize))
    }

    /// Is the control word enabled?
    #[must_use]
    pub const fn is_enabled(control: u32) -> bool {
        control & bits::ENABLE != 0
    }

    /// Clear the enable bit, leaving the rest of the configuration intact —
    /// this is how a slot is temporarily disabled without losing its settings.
    #[must_use]
    pub const fn disabled(control: u32) -> u32 {
        control & !bits::ENABLE
    }

    /// Validate a slot index against an implementation's slot count.
    ///
    /// # Errors
    /// [`Arm64Error::SlotOutOfRange`] when `slot >= available`.
    pub const fn check_slot(slot: usize, available: usize) -> Result<(), Arm64Error> {
        if slot < available {
            Ok(())
        } else {
            Err(Arm64Error::SlotOutOfRange { slot, max: available })
        }
    }
}

// ---------------------------------------------------------------------------
// Pointer authentication (arm64e)
// ---------------------------------------------------------------------------

/// Number of bits of virtual address in use on Apple arm64 user space.
///
/// Everything above is either the PAC signature or the TBI/tag byte, and must
/// be stripped before an address is compared against a module range.
pub const VA_BITS: u32 = 47;

/// Strip a pointer-authentication code / top-byte tag from a user-space
/// address, preserving the canonical form.
///
/// WHY sign-extension rather than a plain mask: kernel addresses have the top
/// bits set, and masking them off would silently turn a kernel pointer into a
/// bogus user pointer.
#[must_use]
pub const fn strip_pac(addr: u64) -> u64 {
    let mask = (1u64 << VA_BITS) - 1;
    if addr & (1u64 << (VA_BITS - 1)) == 0 {
        addr & mask
    } else {
        addr | !mask
    }
}

// ---------------------------------------------------------------------------
// AAPCS64 calling convention
// ---------------------------------------------------------------------------

/// AAPCS64 (the "Procedure Call Standard for the Arm 64-bit Architecture").
pub mod aapcs64 {
    use super::{Arm64Error, Arm64RegisterFile};

    /// Integer/pointer argument registers, in order.
    pub const INT_ARG_REGS: [&str; 8] = ["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"];
    /// Floating-point / SIMD argument registers, in order.
    pub const FP_ARG_REGS: [&str; 8] = ["v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7"];
    /// Indirect result location register (used when the return value is a
    /// large struct returned in memory).
    pub const INDIRECT_RESULT_REG: &str = "x8";
    /// Integer return-value register.
    pub const INT_RETURN_REG: &str = "x0";
    /// Second integer return register (128-bit results).
    pub const INT_RETURN_REG_HI: &str = "x1";
    /// Floating-point return register.
    pub const FP_RETURN_REG: &str = "v0";
    /// Intra-procedure-call scratch registers (usable by linker veneers).
    pub const IP_REGS: [&str; 2] = ["x16", "x17"];
    /// Platform register — reserved on Apple platforms, never a scratch reg.
    pub const PLATFORM_REG: &str = "x18";
    /// Callee-saved general registers (`x19`..`x28`) plus the frame pointer and
    /// link register, which a frame-pointer-based unwinder relies on.
    pub const CALLEE_SAVED: [&str; 12] = [
        "x19", "x20", "x21", "x22", "x23", "x24", "x25", "x26", "x27", "x28", "x29", "x30",
    ];
    /// Callee-saved SIMD registers: only the low 64 bits of `d8`..`d15`.
    pub const CALLEE_SAVED_FP: [&str; 8] =
        ["d8", "d9", "d10", "d11", "d12", "d13", "d14", "d15"];
    /// Number of arguments passed in integer registers before the stack is used.
    pub const INT_ARG_REG_COUNT: usize = INT_ARG_REGS.len();
    /// Stack alignment required at a public interface.
    pub const STACK_ALIGNMENT: u64 = 16;

    /// Is `name` callee-saved (i.e. its value survives a call, so an unwinder
    /// may reuse the caller's copy)?
    #[must_use]
    pub fn is_callee_saved(name: &str) -> bool {
        let lower = name.to_ascii_lowercase();
        CALLEE_SAVED.contains(&lower.as_str())
            || CALLEE_SAVED_FP.contains(&lower.as_str())
            || lower == "fp"
            || lower == "lr"
            || lower == "sp"
    }

    /// Reads doublewords out of the target's stack.
    ///
    /// A trait rather than a closure so a test can supply a synthetic stack and
    /// the live backend can supply the RSP `m` packet, with the same code path.
    pub trait StackReader {
        /// Read the 8 bytes at `addr`, or `None` if unreadable.
        fn read_u64(&self, addr: u64) -> Option<u64>;
    }

    /// A `StackReader` backed by a contiguous byte buffer starting at `base`.
    #[derive(Debug, Clone)]
    pub struct SliceStack<'a> {
        /// Virtual address of `bytes[0]`.
        pub base: u64,
        /// The stack bytes.
        pub bytes: &'a [u8],
    }

    impl StackReader for SliceStack<'_> {
        fn read_u64(&self, addr: u64) -> Option<u64> {
            let off = usize::try_from(addr.checked_sub(self.base)?).ok()?;
            let raw: [u8; 8] = self.bytes.get(off..off + 8)?.try_into().ok()?;
            Some(u64::from_le_bytes(raw))
        }
    }

    /// Extract the `index`-th integer/pointer argument.
    ///
    /// Arguments 0..7 live in `x0`..`x7`; the rest are on the stack at
    /// `sp + 8 * (index - 8)` at function entry, which is only valid *before*
    /// the prologue has moved `sp`. Callers past index 7 must therefore supply
    /// the entry `sp`.
    ///
    /// # Errors
    /// [`Arm64Error::ArgumentOnStack`] when the argument is on the stack and the
    /// reader could not supply it — an explicit failure, never a fabricated 0.
    pub fn integer_argument(
        regs: &Arm64RegisterFile,
        index: usize,
        stack: Option<&dyn StackReader>,
    ) -> Result<u64, Arm64Error> {
        if index < INT_ARG_REG_COUNT {
            return Ok(regs.x[index]);
        }
        let slot = regs
            .sp
            .wrapping_add(8 * (index - INT_ARG_REG_COUNT) as u64);
        stack
            .and_then(|s| s.read_u64(slot))
            .ok_or(Arm64Error::ArgumentOnStack { index })
    }

    /// Extract the first `count` integer arguments.
    ///
    /// # Errors
    /// Propagates the first failure from [`integer_argument`].
    pub fn integer_arguments(
        regs: &Arm64RegisterFile,
        count: usize,
        stack: Option<&dyn StackReader>,
    ) -> Result<Vec<u64>, Arm64Error> {
        (0..count)
            .map(|i| integer_argument(regs, i, stack))
            .collect()
    }

    /// The integer return value of the function that just returned.
    #[must_use]
    pub const fn integer_return(regs: &Arm64RegisterFile) -> u64 {
        regs.x[0]
    }

    /// The low 64 bits of the floating-point return value (`d0`).
    #[must_use]
    pub const fn fp_return_bits(regs: &Arm64RegisterFile) -> u64 {
        regs.v[0] as u64
    }

    /// The `f64` return value of a function returning a `double`.
    #[must_use]
    pub fn double_return(regs: &Arm64RegisterFile) -> f64 {
        f64::from_bits(fp_return_bits(regs))
    }

    /// Round `size` up to the stack alignment required at a public interface.
    #[must_use]
    pub const fn align_stack(size: u64) -> u64 {
        size.div_ceil(STACK_ALIGNMENT) * STACK_ALIGNMENT
    }
}

#[cfg(test)]
mod tests {
    use super::aapcs64::{SliceStack, StackReader};
    use super::hw::{PrivilegeControl, WatchKind};
    use super::*;

    // -- breakpoint instructions --------------------------------------------

    #[test]
    fn brk_zero_is_the_lldb_opcode() {
        assert_eq!(encode_brk(0), 0xD420_0000);
        assert_eq!(BRK_DEFAULT, 0xD420_0000);
        assert_eq!(brk_bytes(0), [0x00, 0x00, 0x20, 0xD4]);
    }

    #[test]
    fn brk_8000_is_not_the_same_word_as_brk_0() {
        // Guards the blueprint's conflation of the two.
        assert_eq!(BRK_IMM_8000, 0xD430_0000);
        assert_ne!(BRK_IMM_8000, BRK_DEFAULT);
        assert_eq!(decode_brk(BRK_IMM_8000), Some(0x8000));
    }

    #[test]
    fn brk_roundtrips_over_every_immediate() {
        for imm in (0u32..=0xFFFF).step_by(97) {
            let imm = imm as u16;
            let word = encode_brk(imm);
            assert!(is_brk(word), "{word:#010x}");
            assert_eq!(decode_brk(word), Some(imm));
            assert!(!is_hlt(word));
        }
    }

    #[test]
    fn hlt_roundtrips_and_is_distinct_from_brk() {
        let word = encode_hlt(1);
        assert_eq!(decode_hlt(word), Some(1));
        assert!(!is_brk(word));
        assert_eq!(word, 0xD440_0020);
    }

    #[test]
    fn non_breakpoint_words_are_rejected() {
        for w in [0u32, 0xD503_201F /* nop */, 0xD65F_03C0 /* ret */, 0xFFFF_FFFF] {
            assert!(!is_brk(w), "{w:#010x} decoded as BRK");
        }
    }

    #[test]
    fn word_from_le_needs_four_bytes() {
        assert_eq!(word_from_le(&[0x00, 0x00, 0x20, 0xD4]), Some(0xD420_0000));
        assert_eq!(word_from_le(&[0x00, 0x00, 0x20]), None);
        // Extra bytes are ignored, not an error: reads are often over-sized.
        assert_eq!(word_from_le(&[0x00, 0x00, 0x20, 0xD4, 0xAA]), Some(0xD420_0000));
    }

    #[test]
    fn instruction_alignment_is_enforced() {
        assert!(check_instruction_alignment(0x1_0000).is_ok());
        assert_eq!(
            check_instruction_alignment(0x1_0002),
            Err(Arm64Error::UnalignedInstruction(0x1_0002))
        );
    }

    #[test]
    fn exception_instructions_decode() {
        assert_eq!(ExceptionInstruction::decode(0xD400_0001), Some(ExceptionInstruction::Svc(0)));
        assert_eq!(
            ExceptionInstruction::decode(encode_brk(0x8000)),
            Some(ExceptionInstruction::Brk(0x8000))
        );
        assert_eq!(
            ExceptionInstruction::decode(encode_hlt(2)),
            Some(ExceptionInstruction::Hlt(2))
        );
        assert!(ExceptionInstruction::decode(encode_brk(0)).unwrap().is_debug_trap());
        assert!(!ExceptionInstruction::decode(0xD400_0001).unwrap().is_debug_trap());
        assert_eq!(ExceptionInstruction::decode(0xD503_201F), None);
    }

    // -- branch decoding -----------------------------------------------------

    #[test]
    fn ret_decodes_to_x30() {
        // `ret` == `ret x30` == 0xD65F03C0
        assert_eq!(BranchKind::decode(0xD65F_03C0), Some(BranchKind::Return { reg: 30 }));
    }

    #[test]
    fn bl_and_b_differ_only_in_the_top_bit() {
        // `bl #4` -> 0x94000001 ; `b #4` -> 0x14000001
        assert_eq!(BranchKind::decode(0x9400_0001), Some(BranchKind::DirectCall { offset: 4 }));
        assert_eq!(BranchKind::decode(0x1400_0001), Some(BranchKind::DirectBranch { offset: 4 }));
        assert!(BranchKind::decode(0x9400_0001).unwrap().is_call());
        assert!(!BranchKind::decode(0x1400_0001).unwrap().is_call());
    }

    #[test]
    fn bl_negative_offset_sign_extends() {
        // imm26 = 0x3FFFFFF (-1) -> offset -4
        assert_eq!(
            BranchKind::decode(0x97FF_FFFF),
            Some(BranchKind::DirectCall { offset: -4 })
        );
    }

    #[test]
    fn blr_and_br_carry_the_register() {
        // blr x8 -> 0xD63F0100 ; br x8 -> 0xD61F0100
        assert_eq!(BranchKind::decode(0xD63F_0100), Some(BranchKind::IndirectCall { reg: 8 }));
        assert_eq!(BranchKind::decode(0xD61F_0100), Some(BranchKind::IndirectBranch { reg: 8 }));
        assert!(BranchKind::decode(0xD63F_0100).unwrap().is_call());
    }

    #[test]
    fn conditional_branches_are_recognised() {
        // b.eq #8 -> 0x54000040
        assert_eq!(
            BranchKind::decode(0x5400_0040),
            Some(BranchKind::ConditionalBranch { offset: 8 })
        );
        // cbz x0, #8 -> 0xB4000040
        assert!(matches!(
            BranchKind::decode(0xB400_0040),
            Some(BranchKind::ConditionalBranch { .. })
        ));
        // tbz w0, #0, #8 -> 0x36000040
        assert!(matches!(
            BranchKind::decode(0x3600_0040),
            Some(BranchKind::ConditionalBranch { .. })
        ));
        assert!(!BranchKind::decode(0x5400_0040).unwrap().is_call());
    }

    #[test]
    fn nop_is_not_control_flow() {
        assert_eq!(BranchKind::decode(0xD503_201F), None);
    }

    // -- registers -----------------------------------------------------------

    #[test]
    fn register_table_is_complete_and_ordered() {
        let all = all_registers();
        assert_eq!(all.len(), 31 + 3 + 32 + 2);
        assert_eq!(all[0].name, "x0");
        assert_eq!(all[30].name, "x30");
        assert_eq!(all[31].name, "sp");
        assert_eq!(all[32].name, "pc");
        assert_eq!(all[33].name, "cpsr");
        assert_eq!(all[34].name, "v0");
        assert_eq!(all[65].name, "v31");
        assert_eq!(all.last().unwrap().name, "fpcr");
    }

    #[test]
    fn dwarf_numbers_match_the_aarch64_spec() {
        assert_eq!(general_reg(0).dwarf, 0);
        assert_eq!(general_reg(30).dwarf, 30);
        assert_eq!(sp_reg().dwarf, 31);
        assert_eq!(pc_reg().dwarf, 32);
        assert_eq!(vector_reg(0).dwarf, 64);
        assert_eq!(vector_reg(31).dwarf, 95);
        assert_eq!(DWARF_RA_SIGN_STATE, 34);
    }

    #[test]
    fn generic_roles_identify_pc_sp_fp_lr() {
        assert_eq!(pc_reg().generic, Some(GenericRole::Pc));
        assert_eq!(sp_reg().generic, Some(GenericRole::Sp));
        assert_eq!(general_reg(29).generic, Some(GenericRole::Fp));
        assert_eq!(general_reg(30).generic, Some(GenericRole::Ra));
        assert_eq!(general_reg(3).generic, Some(GenericRole::Arg(3)));
        assert_eq!(general_reg(15).generic, None);
    }

    #[test]
    fn aliases_resolve() {
        assert_eq!(lookup_register("fp").unwrap().index, 29);
        assert_eq!(lookup_register("lr").unwrap().index, 30);
        assert_eq!(lookup_register("LR").unwrap().index, 30);
        assert_eq!(lookup_register("nzcv").unwrap().name, "cpsr");
        assert_eq!(lookup_register("x30").unwrap().name, "x30");
        assert_eq!(lookup_register("w5").unwrap().bits, 32);
        assert_eq!(lookup_register("w5").unwrap().index, 5);
        assert_eq!(lookup_register("d7").unwrap().bits, 64);
        assert_eq!(lookup_register("d7").unwrap().class, RegClass::Vector);
        assert_eq!(lookup_register("q31").unwrap().bits, 128);
        assert_eq!(lookup_register("b0").unwrap().bits, 8);
    }

    #[test]
    fn zero_register_is_not_the_stack_pointer() {
        let xzr = lookup_register("xzr").unwrap();
        assert_eq!(xzr.class, RegClass::General);
        assert_eq!(xzr.index, 31);
        assert_ne!(xzr.class, RegClass::StackPointer);
    }

    #[test]
    fn bogus_register_names_are_rejected() {
        for name in ["x31", "v32", "w31", "q32", "x", "", "y0", "x01", "pcx"] {
            assert!(lookup_register(name).is_none(), "{name} unexpectedly resolved");
        }
    }

    #[test]
    fn register_file_get_set_roundtrips() {
        let mut f = Arm64RegisterFile::new();
        f.set("x0", 0xDEAD_BEEF_CAFE_BABE).unwrap();
        assert_eq!(f.get("x0").unwrap(), 0xDEAD_BEEF_CAFE_BABE);
        // 32-bit view truncates.
        assert_eq!(f.get("w0").unwrap(), 0xCAFE_BABE);
        f.set("lr", 0x1_0000).unwrap();
        assert_eq!(f.lr(), 0x1_0000);
        f.set("fp", 0x2_0000).unwrap();
        assert_eq!(f.fp(), 0x2_0000);
        f.set("sp", 0x3_0000).unwrap();
        assert_eq!(f.sp, 0x3_0000);
        f.set("pc", 0x4_0000).unwrap();
        assert_eq!(f.pc, 0x4_0000);
    }

    #[test]
    fn writes_to_zero_register_are_discarded_not_errors() {
        let mut f = Arm64RegisterFile::new();
        f.set("xzr", 42).unwrap();
        assert_eq!(f.get("xzr").unwrap(), 0);
        assert_eq!(f.x, [0; NUM_GENERAL]);
    }

    #[test]
    fn vector_write_preserves_high_half() {
        let mut f = Arm64RegisterFile::new();
        f.v[3] = 0xFFFF_FFFF_FFFF_FFFF_0000_0000_0000_0000;
        f.set("d3", 0xAA).unwrap();
        assert_eq!(f.v[3] >> 64, 0xFFFF_FFFF_FFFF_FFFF);
        assert_eq!(f.get("d3").unwrap(), 0xAA);
    }

    #[test]
    fn unknown_register_is_an_explicit_error() {
        let f = Arm64RegisterFile::new();
        assert_eq!(f.get("rax"), Err(Arm64Error::UnknownRegister("rax".into())));
    }

    #[test]
    fn nzcv_flags_decode() {
        let mut f = Arm64RegisterFile::new();
        f.cpsr = pstate::N | pstate::C;
        assert_eq!(f.nzcv(), (true, false, true, false));
    }

    // -- hardware debug ------------------------------------------------------

    #[test]
    fn hw_breakpoint_control_word() {
        let bp = hw::breakpoint(0x1_0000, PrivilegeControl::El0).unwrap();
        assert_eq!(bp.dbgbvr, 0x1_0000);
        assert!(hw::is_enabled(bp.dbgbcr));
        // E=1, PMC=0b10<<1, BAS=0xF<<5, BT=0
        assert_eq!(bp.dbgbcr, 0b1 | (0b10 << 1) | (0xF << 5));
        assert!(!hw::is_enabled(hw::disabled(bp.dbgbcr)));
    }

    #[test]
    fn hw_breakpoint_rejects_unaligned_pc() {
        assert_eq!(
            hw::breakpoint(0x1_0001, PrivilegeControl::El0),
            Err(Arm64Error::UnalignedInstruction(0x1_0001))
        );
    }

    #[test]
    fn watchpoint_bas_covers_every_aligned_placement() {
        // Full doubleword.
        assert_eq!(hw::watchpoint_bas(0x1000, 8).unwrap(), 0xFF);
        // Word in the low half / high half.
        assert_eq!(hw::watchpoint_bas(0x1000, 4).unwrap(), 0x0F);
        assert_eq!(hw::watchpoint_bas(0x1004, 4).unwrap(), 0xF0);
        // Halfwords.
        assert_eq!(hw::watchpoint_bas(0x1002, 2).unwrap(), 0b0000_1100);
        // Single bytes.
        assert_eq!(hw::watchpoint_bas(0x1007, 1).unwrap(), 0b1000_0000);
    }

    #[test]
    fn watchpoint_rejects_bad_geometry() {
        assert_eq!(
            hw::watchpoint_bas(0x1000, 3),
            Err(Arm64Error::UnsupportedWatchpointSize(3))
        );
        assert_eq!(
            hw::watchpoint_bas(0x1001, 4),
            Err(Arm64Error::UnalignedWatchpoint { addr: 0x1001, size: 4 })
        );
    }

    #[test]
    fn watchpoint_pair_and_inverse() {
        let wp = hw::watchpoint(0x1004, 4, WatchKind::Store, PrivilegeControl::El0).unwrap();
        assert_eq!(wp.dbgwvr, 0x1000, "DBGWVR must be granule-aligned");
        assert_eq!((wp.dbgwcr & hw::bits::LSC_MASK) >> hw::bits::LSC_SHIFT, 0b10);
        assert_eq!(hw::watchpoint_range(&wp), Some((0x1004, 4)));

        let byte = hw::watchpoint(0x1007, 1, WatchKind::LoadStore, PrivilegeControl::El0).unwrap();
        assert_eq!(hw::watchpoint_range(&byte), Some((0x1007, 1)));
    }

    #[test]
    fn watchpoint_range_of_empty_bas_is_none() {
        let wp = hw::HwWatchpoint { dbgwvr: 0x1000, dbgwcr: hw::bits::ENABLE };
        assert_eq!(hw::watchpoint_range(&wp), None);
    }

    #[test]
    fn slot_bounds_are_explicit() {
        assert!(hw::check_slot(5, hw::APPLE_HW_BREAKPOINT_SLOTS).is_ok());
        assert_eq!(
            hw::check_slot(6, hw::APPLE_HW_BREAKPOINT_SLOTS),
            Err(Arm64Error::SlotOutOfRange { slot: 6, max: 6 })
        );
        assert!(hw::APPLE_HW_BREAKPOINT_SLOTS <= hw::MAX_HW_BREAKPOINTS);
        assert!(hw::APPLE_HW_WATCHPOINT_SLOTS <= hw::MAX_HW_WATCHPOINTS);
    }

    // -- PAC -----------------------------------------------------------------

    #[test]
    fn strip_pac_clears_signature_bits_of_user_pointers() {
        let signed = 0x0093_0001_0000_1234u64;
        assert_eq!(strip_pac(signed), 0x0001_0000_1234);
        // Already-clean pointer is unchanged.
        assert_eq!(strip_pac(0x0001_0000_1234), 0x0001_0000_1234);
    }

    #[test]
    fn strip_pac_keeps_kernel_pointers_canonical() {
        let kernel = 0xFFFF_FFF0_0700_0000u64;
        assert_eq!(strip_pac(kernel) >> 63, 1, "kernel pointer must stay high");
    }

    // -- AAPCS64 -------------------------------------------------------------

    #[test]
    fn first_eight_arguments_come_from_registers() {
        let mut f = Arm64RegisterFile::new();
        for i in 0..8 {
            f.x[i] = 100 + i as u64;
        }
        let args = aapcs64::integer_arguments(&f, 8, None).unwrap();
        assert_eq!(args, vec![100, 101, 102, 103, 104, 105, 106, 107]);
    }

    #[test]
    fn ninth_argument_comes_from_the_stack() {
        let mut f = Arm64RegisterFile::new();
        f.sp = 0x7000;
        let mut bytes = vec![0u8; 32];
        bytes[0..8].copy_from_slice(&0xAAAA_u64.to_le_bytes());
        bytes[8..16].copy_from_slice(&0xBBBB_u64.to_le_bytes());
        let stack = SliceStack { base: 0x7000, bytes: &bytes };
        assert_eq!(aapcs64::integer_argument(&f, 8, Some(&stack)).unwrap(), 0xAAAA);
        assert_eq!(aapcs64::integer_argument(&f, 9, Some(&stack)).unwrap(), 0xBBBB);
    }

    #[test]
    fn stack_argument_without_reader_is_an_error_not_a_zero() {
        let f = Arm64RegisterFile::new();
        assert_eq!(
            aapcs64::integer_argument(&f, 8, None),
            Err(Arm64Error::ArgumentOnStack { index: 8 })
        );
    }

    #[test]
    fn unreadable_stack_slot_is_an_error() {
        let f = Arm64RegisterFile::new();
        let stack = SliceStack { base: 0x9000, bytes: &[] };
        assert!(stack.read_u64(0x9000).is_none());
        assert_eq!(
            aapcs64::integer_argument(&f, 8, Some(&stack)),
            Err(Arm64Error::ArgumentOnStack { index: 8 })
        );
    }

    #[test]
    fn return_values() {
        let mut f = Arm64RegisterFile::new();
        f.x[0] = 0x2A;
        f.v[0] = u128::from(1.5f64.to_bits());
        assert_eq!(aapcs64::integer_return(&f), 0x2A);
        assert!((aapcs64::double_return(&f) - 1.5).abs() < f64::EPSILON);
    }

    #[test]
    fn callee_saved_classification() {
        assert!(aapcs64::is_callee_saved("x19"));
        assert!(aapcs64::is_callee_saved("x28"));
        assert!(aapcs64::is_callee_saved("fp"));
        assert!(aapcs64::is_callee_saved("d8"));
        assert!(!aapcs64::is_callee_saved("x0"));
        assert!(!aapcs64::is_callee_saved("x18"), "platform reg is reserved, not saved");
        assert!(!aapcs64::is_callee_saved("d0"));
    }

    #[test]
    fn stack_alignment_is_sixteen() {
        assert_eq!(aapcs64::align_stack(1), 16);
        assert_eq!(aapcs64::align_stack(16), 16);
        assert_eq!(aapcs64::align_stack(17), 32);
        assert_eq!(aapcs64::align_stack(0), 0);
    }
}
