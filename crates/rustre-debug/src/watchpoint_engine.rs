//! `watchpoint_engine` — advanced hardware and software watchpoint management.
//!
//! **Intentionally distinct from [`crate::watchpoint_manager`].**
//! This module is the *low-level, architecture-aware* engine.  It owns the CPU
//! debug-register allocation table ([`HwRegisterFile`]), builds the x86 DR7
//! control word ([`X86Dr7Builder`]), and falls back to software page-protect
//! watchpoints when the hardware limit of 4 slots is exhausted.
//!
//! # ARM64 control words
//!
//! The engine builds them alongside the x86 ones: [`WatchpointEngine::arm64_dbgwcr`]
//! returns one DBGWCR per hardware slot (ARM64 has a control register per
//! watchpoint, where x86 packs all four into a single DR7), and
//! [`WatchpointEngine::hw_register_addresses`] returns the matching DBGWVR
//! values. Pair them by slot index.
//!
//! Two register contracts share that address accessor, which is worth stating
//! because it was wrong for one of them until iter 334: DR0-DR3 hold the exact
//! watched address, while DBGWVR holds the **8-byte-aligned base** — its low
//! three bits are RES0 — and the bytes actually watched inside that doubleword
//! are selected by DBGWCR.BAS.
//!
//! The Apple backend does not need any of this: it arms watchpoints through the
//! debugserver's `Z2`/`Z3`/`Z4` packets, so the stub programs the hardware. A
//! backend that programs the registers itself now has the values it needs.
//!
//! `watchpoint_width_support_is_declared_not_assumed`-style guard:
//! `tests::the_arm64_control_word_claim_matches_the_code` keeps this note and
//! the code from drifting apart.
//!
//! `watchpoint_manager` lives one level above: it is a *portable, session-facing*
//! store that uses `rustre_core::Address` and delegates hardware placement
//! decisions to this engine (or to the OS debugger backend directly).
//!
//! Supports:
//! - Hardware watchpoints via CPU debug registers (DR0–DR3 on x86, DBGWVR/DBGWCR on ARM64)
//! - Software watchpoints via memory-protection trap (mprotect + SIGTRAP / guard pages)
//! - Watchpoint types: read, write, execute, access (read|write)
//! - Conditional watchpoints: stop only when value changes to X, or when a register condition holds
//! - Hit counting and one-shot (auto-remove after first hit) watchpoints

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use thiserror::Error;

// ── Opt-2: SIMD scan of hardware debug registers DR0–DR3 ─────────────────────
//
// When a fault address arrives, the hot path in `process_hit` does a linear
// walk over `self.watchpoints` (a HashMap).  For hardware watchpoints the CPU
// can have at most 4 active addresses (DR0–DR3 / DBGWVR0–DBGWVR3).  We can
// check the fault address against all four simultaneously:
//
// • On x86-64 with AVX2: broadcast the fault address into a 256-bit lane,
//   compare four 64-bit slots in one `_mm256_cmpeq_epi64`, return a 4-bit
//   hit mask from `_mm256_movemask_pd`.
// • On all other targets (including Windows-x86_64 without AVX2): fall back
//   to a tiny scalar loop that the auto-vectoriser will turn into SSE2 or
//   better anyway.
//
// The function is intentionally free-standing (takes a plain `[u64; 4]`) so
// it can be tested and fuzzed without a live `WatchpointEngine`.

/// Check `fault_addr` against four hardware debug-register addresses in one
/// SIMD operation.
///
/// `hw_addrs` is a 4-element array where `hw_addrs[i]` holds the address
/// currently loaded into debug register `i` (0 for an unused slot).
///
/// Returns a 4-bit mask where bit `i` is set if `fault_addr == hw_addrs[i]`.
///
/// # Note on slot-0 ambiguity
/// A slot whose address is `0` can produce a false positive if the fault
/// address is also `0`. Real debug-register addresses are always in kernel- or
/// user-space VA ranges and are never 0, so this is safe in practice.
#[must_use]
pub fn simd_scan_hw_registers(fault_addr: u64, hw_addrs: [u64; 4]) -> u8 {
    #[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
    {
        // SAFETY: target_feature = "avx2" guarantees the instructions are
        // available; the pointer casts are to correctly-sized aligned temporaries
        // allocated on the stack.
        unsafe {
            use std::arch::x86_64::{
                __m256i,
                _mm256_cmpeq_epi64,
                _mm256_loadu_si256,
                _mm256_movemask_pd,
                _mm256_set1_epi64x,
                _mm256_castsi256_pd,
            };

            let needle = _mm256_set1_epi64x(fault_addr as i64);
            let haystack = _mm256_loadu_si256(hw_addrs.as_ptr().cast::<__m256i>());
            let eq = _mm256_cmpeq_epi64(needle, haystack);
            let mask = _mm256_movemask_pd(_mm256_castsi256_pd(eq));
            (mask & 0xF) as u8
        }
    }
    #[cfg(not(all(target_arch = "x86_64", target_feature = "avx2")))]
    {
        // Scalar fallback; the compiler auto-vectorises this on SSE2+ targets.
        let mut mask: u8 = 0;
        for (i, &addr) in hw_addrs.iter().enumerate() {
            if addr == fault_addr {
                mask |= 1u8 << i;
            }
        }
        mask
    }
}

/// Runtime-dispatch wrapper: tries AVX2 if the CPU supports it at runtime,
/// otherwise falls back to the scalar path.
///
/// Use this when the binary is compiled without a blanket `target_feature` so
/// that users on older CPUs still get correct results.
#[must_use]
pub fn simd_scan_hw_registers_runtime(fault_addr: u64, hw_addrs: [u64; 4]) -> u8 {
    #[cfg(target_arch = "x86_64")]
    if std::is_x86_feature_detected!("avx2") {
        // SAFETY: we just confirmed AVX2 is available.
        unsafe {
            use std::arch::x86_64::{
                __m256i,
                _mm256_cmpeq_epi64,
                _mm256_loadu_si256,
                _mm256_movemask_pd,
                _mm256_set1_epi64x,
                _mm256_castsi256_pd,
            };
            let needle = _mm256_set1_epi64x(fault_addr as i64);
            let haystack = _mm256_loadu_si256(hw_addrs.as_ptr().cast::<__m256i>());
            let eq = _mm256_cmpeq_epi64(needle, haystack);
            let mask = _mm256_movemask_pd(_mm256_castsi256_pd(eq));
            return (mask & 0xF) as u8;
        }
    }
    // Scalar fallback.
    let mut mask: u8 = 0;
    for (i, &addr) in hw_addrs.iter().enumerate() {
        if addr == fault_addr {
            mask |= 1u8 << i;
        }
    }
    mask
}

// ─────────────────────────────────────────────────────────────────────────────
// Error
// ─────────────────────────────────────────────────────────────────────────────

/// Errors produced by the watchpoint engine.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum WatchpointError {
    #[error("watchpoint already exists at {0:#x}")]
    AlreadyExists(u64),
    #[error("watchpoint not found: id {0}")]
    NotFound(u64),
    #[error("no hardware debug register available")]
    NoHwRegisterAvailable,
    #[error("address {0:#x} is not aligned for size {1}")]
    AlignmentError(u64, u8),
    #[error("watchpoint size {0} is not supported (must be 1, 2, 4, or 8)")]
    InvalidSize(u8),
    #[error("condition expression error: {0}")]
    ConditionError(String),
    #[error("platform error: {0}")]
    Platform(String),
    #[error("unsupported on this architecture: {0}")]
    Unsupported(String),
}

// ─────────────────────────────────────────────────────────────────────────────
// WatchpointType
// ─────────────────────────────────────────────────────────────────────────────

/// What kind of memory access triggers a watchpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WatchpointType {
    /// Fire on any read of the watched range.
    Read,
    /// Fire on any write to the watched range.
    Write,
    /// Fire on instruction fetch (execution breakpoint via data debug register).
    Execute,
    /// Fire on any read or write (but not execute).
    Access,
}

impl WatchpointType {
    /// The [`crate::BreakpointKind`] that arms this access type.
    ///
    /// The engine and the `Debugger` trait describe the same hardware with two
    /// vocabularies, and until now nothing converted between them — so a caller
    /// holding an engine watchpoint could not ask the debugger to arm it and
    /// had to program the debug registers itself. Two things programming DR7
    /// from two models of the world is how they drift apart.
    ///
    /// `Execute` maps to [`crate::BreakpointKind::Hardware`]: an execution trap
    /// through a debug register is not a data watchpoint, and calling it one
    /// would arm the wrong `R/W` bits.
    #[must_use]
    pub const fn as_breakpoint_kind(self) -> crate::BreakpointKind {
        match self {
            Self::Read => crate::BreakpointKind::DataRead,
            Self::Write => crate::BreakpointKind::DataWrite,
            Self::Access => crate::BreakpointKind::DataReadWrite,
            Self::Execute => crate::BreakpointKind::Hardware,
        }
    }

    /// Inverse of [`Self::as_breakpoint_kind`].
    ///
    /// `None` for [`crate::BreakpointKind::Software`], which no debug register
    /// can express — answering `Write` there would be a fabricated conversion.
    #[must_use]
    pub const fn from_breakpoint_kind(kind: crate::BreakpointKind) -> Option<Self> {
        match kind {
            crate::BreakpointKind::DataRead => Some(Self::Read),
            crate::BreakpointKind::DataWrite => Some(Self::Write),
            crate::BreakpointKind::DataReadWrite => Some(Self::Access),
            crate::BreakpointKind::Hardware => Some(Self::Execute),
            crate::BreakpointKind::Software => None,
        }
    }
}

impl fmt::Display for WatchpointType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read => write!(f, "read"),
            Self::Write => write!(f, "write"),
            Self::Execute => write!(f, "execute"),
            Self::Access => write!(f, "read|write"),
        }
    }
}

impl WatchpointType {
    /// Convert to the x86 DR7 condition bits (R/W field, 2 bits).
    ///
    /// | Value | Meaning     |
    /// |-------|-------------|
    /// | 0b00  | Execute     |
    /// | 0b01  | Write       |
    /// | 0b11  | Read/Write  |
    /// | 0b10  | I/O (rare)  |
    #[must_use]
    pub const fn x86_dr7_rw_bits(self) -> u8 {
        match self {
            Self::Execute => 0b00,
            Self::Write => 0b01,
            Self::Access | Self::Read => 0b11, // x86 doesn't distinguish read-only; use read|write
        }
    }

    /// Convert to ARM64 DBGWCR BAS/LSC fields.
    /// Returns `(LSC, BAS_mask)` where LSC is the Load/Store Control bits.
    #[must_use]
    pub const fn arm64_dbgwcr_lsc(self) -> u8 {
        match self {
            Self::Read => 0b01,
            Self::Write => 0b10,
            Self::Access | Self::Execute => 0b11, // execution via DBGBCR, not DBGWCR; best effort
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// WatchpointCondition
// ─────────────────────────────────────────────────────────────────────────────

/// An optional predicate that must be true for the watchpoint to stop execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WatchpointCondition {
    /// Stop only when the watched memory value equals `expected`.
    ValueEquals { expected: u64 },
    /// Stop only when the watched memory value changes from its previous reading
    /// to `new_value`.
    ValueChangesTo { new_value: u64 },
    /// Stop only when the watched memory value changes at all (any change).
    AnyChange,
    /// Stop only when register `name` equals `value` at the time of the access.
    RegisterEquals { name: String, value: u64 },
    /// An arbitrary expression string evaluated by the debug engine's expression
    /// evaluator (e.g. `"rax > 10 && [rsp+8] == 0xdead_beef"`).
    Expression(String),
}

impl fmt::Display for WatchpointCondition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ValueEquals { expected } => write!(f, "value == {expected:#x}"),
            Self::ValueChangesTo { new_value } => write!(f, "value -> {new_value:#x}"),
            Self::AnyChange => write!(f, "any_change"),
            Self::RegisterEquals { name, value } => write!(f, "{name} == {value:#x}"),
            Self::Expression(e) => write!(f, "expr({e})"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// WatchpointImpl
// ─────────────────────────────────────────────────────────────────────────────

/// How a watchpoint is backed at the platform level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WatchpointImpl {
    /// Uses a CPU debug register (DR0–DR3 on x86, DBGWVR on ARM64).
    Hardware {
        /// Debug register index (0–3 on x86/ARM64).
        reg_index: u8,
    },
    /// Uses `mprotect` to remove the page's permission, causing a SIGSEGV/SIGTRAP
    /// that the debugger intercepts and emulates as a watchpoint.
    SoftwarePageProtect {
        /// Original page protection flags before modification.
        original_prot: u32,
    },
}

// ─────────────────────────────────────────────────────────────────────────────
// Watchpoint
// ─────────────────────────────────────────────────────────────────────────────

/// A single watchpoint descriptor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Watchpoint {
    /// Unique monotonically-increasing identifier.
    pub id: u64,
    /// Start address of the watched memory region.
    pub address: u64,
    /// Number of bytes watched (hardware: 1, 2, 4, or 8; software: any page-aligned size).
    pub size: u8,
    /// Access type that triggers the watchpoint.
    pub watch_type: WatchpointType,
    /// Whether the watchpoint is currently active.
    pub enabled: bool,
    /// Optional predicate — if `None` the watchpoint always stops.
    pub condition: Option<WatchpointCondition>,
    /// How many times this watchpoint has fired (regardless of condition).
    pub hit_count: u64,
    /// If `true`, the watchpoint is removed automatically after the first hit.
    pub one_shot: bool,
    /// Implementation detail (hardware register or software page-protect).
    pub implementation: WatchpointImpl,
    /// The last observed value of the watched memory (used for `AnyChange` / `ValueChangesTo`).
    pub last_value: Option<u64>,
    /// Optional human-readable label.
    pub label: Option<String>,
}

impl Watchpoint {
    /// Evaluate the condition against `current_value` and the register snapshot.
    ///
    /// Returns `true` if the debugger should stop, `false` if it should silently
    /// resume.
    #[must_use]
    /// `current_value` is `None` when the watched memory could not be read.
    ///
    /// That case used to arrive here as `0`, courtesy of an `unwrap_or(0)` at
    /// the call site, so a value that was never read was compared as if it had
    /// been: `ValueEquals { expected: 0 }` "matched" on an unreadable location,
    /// `AnyChange` saw a change from whatever was last known to zero, and a
    /// one-shot watchpoint was consumed by a match that never happened — gone
    /// for good, with nothing to show the user why.
    ///
    /// A condition that needs the value and cannot have it is answered `true`:
    /// stopping on an unverifiable condition is visible and recoverable, while
    /// silently not stopping is neither. [`WatchpointEngine::process_hit`] pairs
    /// this with refusing to consume a one-shot on a condition it could not
    /// evaluate.
    pub fn should_stop(&self, current_value: Option<u64>, regs: &HashMap<String, u64>) -> bool {
        let Some(current_value) = current_value else {
            // Only the value-dependent conditions are affected; the others fall
            // through to the normal path below with a placeholder they ignore.
            return match &self.condition {
                Some(WatchpointCondition::ValueEquals { .. } |
WatchpointCondition::ValueChangesTo { .. } | WatchpointCondition::AnyChange) => true,
                _ => self.should_stop(Some(0), regs),
            };
        };
        match &self.condition {
            None => true,
            Some(WatchpointCondition::ValueEquals { expected }) => current_value == *expected,
            Some(WatchpointCondition::ValueChangesTo { new_value }) => {
                current_value == *new_value
                    && self.last_value.is_none_or(|v| v != current_value)
            }
            Some(WatchpointCondition::AnyChange) => {
                self.last_value.is_none_or(|v| v != current_value)
            }
            Some(WatchpointCondition::RegisterEquals { name, value }) => {
                // A register that is not in the map cannot be compared. It used
                // to arrive as `u64::MAX`, so an absent or misspelled register
                // silently made the condition false and the watchpoint never
                // stopped — the user sees a watchpoint that simply never fires,
                // with nothing pointing at the name. (And a condition expecting
                // `u64::MAX` matched on absence.) Same rule as the value
                // conditions above: unverifiable means stop, not skip.
                regs.get(name.as_str()).copied().is_none_or(|actual| actual == *value)
            }
            Some(WatchpointCondition::Expression(_expr)) => {
                // In a real implementation this delegates to the expression evaluator;
                // here we conservatively return true (always stop).
                true
            }
        }
    }
}

impl fmt::Display for Watchpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Watchpoint#{} [{:#x}+{}] {} enabled={} hits={} one_shot={}",
            self.id,
            self.address,
            self.size,
            self.watch_type,
            self.enabled,
            self.hit_count,
            self.one_shot,
        )?;
        if let Some(c) = &self.condition {
            write!(f, " if={c}")?;
        }
        if let Some(l) = &self.label {
            write!(f, " ({l})")?;
        }
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// HwRegisterFile — x86 DR0–DR3 / ARM64 DBGWVR0–DBGWVR3
// ─────────────────────────────────────────────────────────────────────────────

/// Tracks which hardware debug registers are in use.
#[derive(Debug, Clone, Default)]
pub struct HwRegisterFile {
    /// `slots[i]` is `Some(watchpoint_id)` if register i is allocated.
    pub slots: [Option<u64>; 4],
}

impl HwRegisterFile {
    /// Allocate the next free slot. Returns the slot index or an error.
    ///
    /// # Errors
    ///
    /// Returns `WatchpointError::NoHwRegisterAvailable` if all slots are occupied.
    pub fn alloc(&mut self, wp_id: u64) -> Result<u8, WatchpointError> {
        for (i, slot) in self.slots.iter_mut().enumerate() {
            if slot.is_none() {
                *slot = Some(wp_id);
                return Ok(u8::try_from(i).unwrap_or(u8::MAX));
            }
        }
        Err(WatchpointError::NoHwRegisterAvailable)
    }

    /// Free the slot associated with `wp_id`.
    pub fn free(&mut self, wp_id: u64) {
        for slot in &mut self.slots {
            if *slot == Some(wp_id) {
                *slot = None;
            }
        }
    }

    /// Return the slot index for `wp_id`, if any.
    #[must_use]
    pub fn slot_of(&self, wp_id: u64) -> Option<u8> {
        self.slots
            .iter()
            .enumerate()
            .find_map(|(i, s)| if *s == Some(wp_id) { Some(u8::try_from(i).unwrap_or(u8::MAX)) } else { None })
    }

    /// Number of free slots remaining.
    #[must_use]
    pub fn free_count(&self) -> usize {
        self.slots.iter().filter(|s| s.is_none()).count()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// X86Dr7Builder — construct the DR7 control register value
// ─────────────────────────────────────────────────────────────────────────────

/// Builds the x86 DR7 (Debug Control Register) value from per-slot settings.
///
/// DR7 layout (simplified):
/// ```text
/// bits 0,2,4,6   : L0,L1,L2,L3 — local enable for each DR
/// bits 1,3,5,7   : G0,G1,G2,G3 — global enable
/// bits 16-17     : R/W0 (condition for DR0)
/// bits 18-19     : LEN0 (length for DR0)
/// … (DR1=20-23, DR2=24-27, DR3=28-31)
/// ```
#[derive(Debug, Clone, Default)]
pub struct X86Dr7Builder {
    pub value: u64,
}

impl X86Dr7Builder {
    /// Enable local breakpoint for slot `i`.
    pub const fn enable_local(&mut self, slot: u8) {
        self.value |= 1u64 << (slot * 2);
    }

    /// Disable local breakpoint for slot `i`.
    pub const fn disable_local(&mut self, slot: u8) {
        self.value &= !(1u64 << (slot * 2));
    }

    /// Set the condition (R/W) bits for slot `i`.
    pub const fn set_condition(&mut self, slot: u8, rw_bits: u8) {
        let shift = 16 + slot * 4;
        self.value &= !(0b11u64 << shift);
        self.value |= (rw_bits as u64 & 0b11) << shift;
    }

    /// Set the length bits for slot `i`.
    ///
    /// | size | LEN bits |
    /// |------|----------|
    /// | 1    | 0b00     |
    /// | 2    | 0b01     |
    /// | 8    | 0b10     |
    /// | 4    | 0b11     |
    /// Returns `false` — leaving `DR7` untouched — for a size the hardware
    /// cannot express.
    ///
    /// It used to fold every unrecognised size into `0b00`, which is ONE BYTE:
    /// asking to watch 3 or 16 bytes produced a watchpoint over the first byte
    /// and said nothing. The caller is told the region is covered while a write
    /// to its second byte goes unnoticed — the failure mode a watchpoint exists
    /// to rule out. `crate::x86_encode_watchpoint_dr7`, the encoder the backends
    /// actually use, has always refused those sizes; this is the same rule on the
    /// other of the two paths that program the same register.
    pub const fn set_length(&mut self, slot: u8, size: u8) -> bool {
        let len_bits: u64 = match size {
            1 => 0b00,
            2 => 0b01,
            8 => 0b10,
            4 => 0b11,
            _ => return false,
        };
        let shift = 18 + slot * 4;
        self.value &= !(0b11u64 << shift);
        self.value |= len_bits << shift;
        true
    }

    /// Apply one watchpoint's settings to the DR7 value.
    /// Returns `false` and changes NOTHING when the size is not encodable.
    ///
    /// Enabling the slot anyway would arm a watchpoint of the wrong width, which
    /// is worse than not arming it: the caller has been told the region is
    /// watched.
    pub const fn apply_watchpoint(&mut self, slot: u8, rw_bits: u8, size: u8, enabled: bool) -> bool {
        if enabled {
            self.enable_local(slot);
        } else {
            self.disable_local(slot);
        }
        self.set_condition(slot, rw_bits);
        if !self.set_length(slot, size) {
            self.disable_local(slot);
            return false;
        }
        true
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Arm64DbgwcrBuilder — ARM64 DBGWCR register value builder
// ─────────────────────────────────────────────────────────────────────────────

/// Builds the ARM64 DBGWCR (Debug Watchpoint Control Register) value.
///
/// Relevant DBGWCR fields:
/// - bit 0       : EN — enable
/// - bits 3–4    : LSC — Load/Store Control (01=load, 10=store, 11=both)
/// - bits 5–12   : BAS — Byte Address Select (which bytes in the word are watched)
/// - bits 20–28  : MASK — larger-range mask (for aligned power-of-2 regions)
#[derive(Debug, Clone, Default)]
pub struct Arm64DbgwcrBuilder {
    pub value: u32,
}

impl Arm64DbgwcrBuilder {
    pub const fn enable(&mut self) {
        self.value |= 1;
    }

    pub const fn disable(&mut self) {
        self.value &= !1;
    }

    pub const fn set_lsc(&mut self, lsc: u8) {
        self.value &= !(0b11 << 3);
        self.value |= ((lsc & 0b11) as u32) << 3;
    }

    /// Set BAS (Byte Address Select) for a `size`-byte region starting at
    /// `offset` within the aligned 8-byte word.
    /// Returns `false` — leaving `BAS` untouched — for a request the field
    /// cannot express.
    ///
    /// It used to fold every unrecognised size into `0xff`, which watches ALL
    /// EIGHT bytes of the doubleword. That is the mirror image of the x86 defect
    /// fixed alongside it, and the more misleading of the two: a 3-byte request
    /// became an 8-byte watch, so a write to the NEIGHBOURING field reported as a
    /// hit on the watched one — a false positive presented as a measurement.
    ///
    /// A region that straddles the doubleword `BAS` indexes is refused too: there
    /// is no mask that expresses it, and rounding to one there would widen the
    /// watch just as silently.
    pub const fn set_bas(&mut self, offset: u8, size: u8) -> bool {
        let mask: u8 = match size {
            1 => 0x01,
            2 => 0x03,
            4 => 0x0f,
            8 => 0xff,
            _ => return false,
        };
        if offset as u16 + size as u16 > 8 {
            return false;
        }
        // Contiguous is not enough: the selected bytes must be NATURALLY
        // ALIGNED within the doubleword.
        //
        // A four-byte watch at offset 2 gives `BAS = 0x3C` — eight contiguous
        // bits, and the length check above is happy with it — but the
        // architecture defines the byte-select field only for aligned regions;
        // anything else is CONSTRAINED UNPREDICTABLE, which in practice means a
        // watchpoint that may fire on the wrong access or not at all.
        //
        // Not reachable through `add()` today, because `validate_alignment`
        // already requires `address % size == 0` and the offset is
        // `address % 8`. But this is a `pub` method on a `pub` type: the
        // guarantee has to live where the value is built, not in whichever
        // caller happens to check first.
        if !offset.is_multiple_of(size) {
            return false;
        }
        self.value &= !(0xff << 5);
        self.value |= ((mask << offset) as u32) << 5;
        true
    }

    /// Program the whole control word through the encoder the backends use.
    ///
    /// `crate::arm64_encode_watchpoint_wcr` is the one the macOS backend calls,
    /// and it sets a field this builder never touched: `PAC = 0b10` (EL0). With
    /// `PAC = 0b00` — the value every word this builder produced carried — the
    /// watchpoint is armed and **can never fire**, because no user-mode access
    /// matches. Silence that looks exactly like "the program never touched it".
    ///
    /// # Returns
    /// `false`, changing nothing, when the request is not encodable.
    pub fn apply_watchpoint(&mut self, addr: u64, kind: crate::BreakpointKind, size: u8) -> bool {
        match crate::arm64_encode_watchpoint_wcr(addr, kind, size) {
            Some(word) => {
                self.value = u32::try_from(word).unwrap_or(self.value);
                true
            }
            None => false,
        }
    }

    /// Set MASK field for large power-of-2 aligned ranges (≥ 8 bytes).
    pub const fn set_mask(&mut self, log2_size: u8) {
        self.value &= !(0x1f << 20);
        self.value |= ((log2_size & 0x1f) as u32) << 20;
    }
}

// ── Opt-8: cold helpers for rare error paths ──────────────────────────────────

/// Alignment error constructor marked `#[cold]` so the compiler keeps it off
/// the hot allocation path and doesn't inline the error-string formatting into
/// the caller.
#[cold]
#[inline(never)]
const fn cold_alignment_err(addr: u64, size: u8) -> WatchpointError {
    WatchpointError::AlignmentError(addr, size)
}

/// Already-watched error constructor — cold because `add` is called at most a
/// handful of times per session, never in a tight loop.
#[cold]
#[inline(never)]
const fn cold_already_exists_err(addr: u64) -> WatchpointError {
    WatchpointError::AlreadyExists(addr)
}

// ─────────────────────────────────────────────────────────────────────────────
// WatchpointHit — event emitted when a watchpoint fires
// ─────────────────────────────────────────────────────────────────────────────

/// Information about a watchpoint that has just fired.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatchpointHit {
    /// The watchpoint that fired.
    pub watchpoint_id: u64,
    /// Address of the memory access that triggered the watchpoint.
    pub access_address: u64,
    /// Program counter at the time of the access.
    pub pc: u64,
    /// Whether this was a read or write access (best effort from the OS).
    pub was_write: bool,
    /// Value in the watched memory after the access.
    pub new_value: Option<u64>,
    /// Value in the watched memory before the access (if tracked).
    pub old_value: Option<u64>,
    /// The condition evaluation result (`true` → debugger stopped).
    pub condition_matched: bool,
    /// Running hit count for this watchpoint (including this hit).
    pub hit_count: u64,
}

impl fmt::Display for WatchpointHit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "WatchpointHit: wp#{} at pc={:#x} addr={:#x} {} hit#{}",
            self.watchpoint_id,
            self.pc,
            self.access_address,
            if self.was_write { "WRITE" } else { "READ" },
            self.hit_count,
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// WatchpointEngine
// ─────────────────────────────────────────────────────────────────────────────

/// Central manager for all watchpoints in a debug session.
///
/// The engine is architecture-aware: it prefers hardware watchpoints and falls
/// back to software (page-protection) watchpoints when the hardware limit (4
/// registers) is exhausted or the watch size is too large.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TargetArch {
    X86_64,
    X86_32,
    Arm64,
    Arm32,
    Other,
}

/// The watchpoint engine.
pub struct WatchpointEngine {
    /// All registered watchpoints, keyed by ID.
    watchpoints: HashMap<u64, Watchpoint>,
    /// Next ID to assign.
    next_id: u64,
    /// Hardware debug register allocation state.
    hw_regs: HwRegisterFile,
    /// DR7 builder (x86 only).
    dr7: X86Dr7Builder,
    /// One DBGWCR per hardware slot (ARM64 has a control register per
    /// watchpoint, unlike x86 where a single DR7 covers all four).
    dbgwcr: [Arm64DbgwcrBuilder; 4],
    /// Target architecture.
    arch: TargetArch,
    /// Maximum number of hardware watchpoints supported.
    hw_limit: u8,
}

impl WatchpointEngine {
    /// Create a new engine for the specified architecture.
    #[must_use]
    pub fn new(arch: TargetArch) -> Self {
        let hw_limit = match arch {
            TargetArch::X86_64 | TargetArch::X86_32 | TargetArch::Arm64 | TargetArch::Arm32 => 4,
            TargetArch::Other => 0,
        };
        Self {
            watchpoints: HashMap::new(),
            next_id: 1,
            hw_regs: HwRegisterFile::default(),
            dr7: X86Dr7Builder::default(),
            dbgwcr: Default::default(),
            arch,
            hw_limit,
        }
    }

    /// Maximum number of hardware watchpoints supported by the target architecture.
    #[must_use]
    pub const fn hw_limit(&self) -> u8 { self.hw_limit }

    /// True if all hardware watchpoint slots are currently in use.
    #[must_use]
    pub fn hw_slots_exhausted(&self) -> bool {
        self.hw_regs.free_count() == 0 || self.hw_limit == 0
    }

    // ── Validation ────────────────────────────────────────────────────────────

    const fn validate_hw_size(size: u8) -> Result<(), WatchpointError> {
        match size {
            1 | 2 | 4 | 8 => Ok(()),
            _ => Err(WatchpointError::InvalidSize(size)),
        }
    }

    fn validate_alignment(addr: u64, size: u8) -> Result<(), WatchpointError> {
        if size > 1 && !addr.is_multiple_of(u64::from(size)) {
            return Err(cold_alignment_err(addr, size));
        }
        Ok(())
    }

    fn address_already_watched(&self, addr: u64) -> bool {
        self.watchpoints.values().any(|w| w.address == addr && w.enabled)
    }

    // ── Add / Remove ──────────────────────────────────────────────────────────

    /// Add a new watchpoint. Automatically chooses hardware vs. software
    /// implementation based on availability and size.
    ///
    /// # Errors
    ///
    /// Returns `WatchpointError` if the address is already watched or hardware allocation fails.
    pub fn add(
        &mut self,
        address: u64,
        size: u8,
        watch_type: WatchpointType,
        condition: Option<WatchpointCondition>,
        one_shot: bool,
        label: Option<String>,
    ) -> Result<u64, WatchpointError> {
        if self.address_already_watched(address) {
            return Err(cold_already_exists_err(address));
        }

        let id = self.next_id;
        self.next_id += 1;

        // Try hardware first (only for sizes 1/2/4/8 and if registers available).
        let implementation = if self.hw_regs.free_count() > 0
            && Self::validate_hw_size(size).is_ok()
            && Self::validate_alignment(address, size).is_ok()
        {
            let slot = self.hw_regs.alloc(id)?;
            // Configure DR7 for x86.
            if matches!(self.arch, TargetArch::X86_64 | TargetArch::X86_32) {
                self.dr7.apply_watchpoint(slot, watch_type.x86_dr7_rw_bits(), size, true);
            }
            // ARM64: one DBGWCR per slot. DBGWVR holds the 8-byte-aligned base
            // and BAS selects which bytes inside that doubleword are watched,
            // so the offset within the word has to be carried into BAS here.
            if matches!(self.arch, TargetArch::Arm64 | TargetArch::Arm32)
                && let Some(ctl) = self.dbgwcr.get_mut(slot as usize)
            {
                ctl.enable();
                ctl.set_lsc(watch_type.arm64_dbgwcr_lsc());
                // Refuses instead of widening; the caller already validated the
                // size through `validate_hw_size`, so a `false` here means the
                // region straddles the doubleword and no mask expresses it.
                if !ctl.set_bas((address % 8) as u8, size) {
                    // Give the slot back and refuse.
                    //
                    // Disabling the control word left the watchpoint recorded as
                    // `Hardware { reg_index: slot }` and the slot allocated: the
                    // caller received `Ok(id)` for something that is armed
                    // nowhere and can never fire, while one of the four hardware
                    // slots stayed consumed until an explicit `remove`. A
                    // success that hands back a dead watchpoint AND eats a slot
                    // is worse than an error.
                    ctl.disable();
                    self.hw_regs.free(id);
                    return Err(cold_alignment_err(address, size));
                }
            }
            WatchpointImpl::Hardware { reg_index: slot }
        } else {
            // Fall back to software page-protect watchpoint.
            WatchpointImpl::SoftwarePageProtect { original_prot: 0x04 /* RW */ }
        };

        let wp = Watchpoint {
            id,
            address,
            size,
            watch_type,
            enabled: true,
            condition,
            hit_count: 0,
            one_shot,
            implementation,
            last_value: None,
            label,
        };

        self.watchpoints.insert(id, wp);
        Ok(id)
    }

    /// Add a hardware watchpoint, returning an error if no hardware slots are
    /// available.
    ///
    /// # Errors
    ///
    /// Returns `WatchpointError` if no hardware slot is available, size is invalid, or alignment fails.
    pub fn add_hardware(
        &mut self,
        address: u64,
        size: u8,
        watch_type: WatchpointType,
        condition: Option<WatchpointCondition>,
        one_shot: bool,
        label: Option<String>,
    ) -> Result<u64, WatchpointError> {
        Self::validate_hw_size(size)?;
        Self::validate_alignment(address, size)?;
        if self.hw_regs.free_count() == 0 {
            return Err(WatchpointError::NoHwRegisterAvailable);
        }
        self.add(address, size, watch_type, condition, one_shot, label)
    }

    /// Add a software (page-protect) watchpoint regardless of hardware slot
    /// availability.
    ///
    /// # Errors
    ///
    /// Returns `WatchpointError::AlreadyExists` if the address is already watched.
    pub fn add_software(
        &mut self,
        address: u64,
        size: u8,
        watch_type: WatchpointType,
        condition: Option<WatchpointCondition>,
        one_shot: bool,
        label: Option<String>,
    ) -> Result<u64, WatchpointError> {
        if self.address_already_watched(address) {
            return Err(WatchpointError::AlreadyExists(address));
        }
        let id = self.next_id;
        self.next_id += 1;
        let wp = Watchpoint {
            id,
            address,
            size,
            watch_type,
            enabled: true,
            condition,
            hit_count: 0,
            one_shot,
            implementation: WatchpointImpl::SoftwarePageProtect { original_prot: 0x04 },
            last_value: None,
            label,
        };
        self.watchpoints.insert(id, wp);
        Ok(id)
    }

    /// Remove a watchpoint by ID.
    ///
    /// # Errors
    ///
    /// Returns `WatchpointError::NotFound` if no watchpoint has the given ID.
    pub fn remove(&mut self, id: u64) -> Result<Watchpoint, WatchpointError> {
        let wp = self.watchpoints.remove(&id).ok_or(WatchpointError::NotFound(id))?;
        if let WatchpointImpl::Hardware { reg_index } = wp.implementation {
            // Disable the DR7 slot BEFORE freeing: `slot_of(id)` after `free(id)`
            // returns `None`, which silently left the enable bit set (bug found
            // 2026-07-18 while wiring watchpoints to the live MCP surface).
            if matches!(self.arch, TargetArch::X86_64 | TargetArch::X86_32) {
                self.dr7.disable_local(reg_index);
            }
            if let Some(ctl) = self.dbgwcr.get_mut(reg_index as usize) {
                *ctl = Arm64DbgwcrBuilder::default();
            }
            self.hw_regs.free(id);
        }
        Ok(wp)
    }

    /// Enable or disable a watchpoint.
    ///
    /// # Errors
    ///
    /// Returns `WatchpointError::NotFound` if no watchpoint has the given ID.
    pub fn set_enabled(&mut self, id: u64, enabled: bool) -> Result<(), WatchpointError> {
        let wp = self.watchpoints.get_mut(&id).ok_or(WatchpointError::NotFound(id))?;
        wp.enabled = enabled;
        if let WatchpointImpl::Hardware { reg_index } = wp.implementation {
            if matches!(self.arch, TargetArch::X86_64 | TargetArch::X86_32) {
                if enabled {
                    self.dr7.enable_local(reg_index);
                } else {
                    self.dr7.disable_local(reg_index);
                }
            } else if let Some(ctl) = self.dbgwcr.get_mut(reg_index as usize) {
                if enabled {
                    ctl.enable();
                } else {
                    ctl.disable();
                }
            }
        }
        Ok(())
    }

    // ── Hit processing ────────────────────────────────────────────────────────

    /// Called by the debugger when a watchpoint exception fires at `access_address`.
    ///
    /// Matches the exception to a registered watchpoint, evaluates the condition,
    /// updates hit counts and last-value, removes one-shot watchpoints, and
    /// returns a `WatchpointHit` descriptor.
    ///
    /// Returns `None` if no watchpoint matches `access_address`.
    pub fn process_hit(
        &mut self,
        access_address: u64,
        pc: u64,
        was_write: bool,
        current_value: Option<u64>,
        regs: &HashMap<String, u64>,
    ) -> Option<WatchpointHit> {
        // Opt-2: fast SIMD pre-check across all four HW debug-register addresses.
        // If none of DR0–DR3 covers `access_address` we can skip the HashMap
        // scan entirely (saves ~40 ns on a 10-watchpoint map when the fault is
        // a software watchpoint or an unrelated exception).
        let hw_addrs = self.hw_register_addresses();
        let hw_mask = simd_scan_hw_registers_runtime(access_address, hw_addrs);

        // Find the watchpoint whose range covers `access_address`.
        let id = self
            .watchpoints
            .values()
            .find(|w| {
                if matches!(w.implementation, WatchpointImpl::Hardware { .. }) && hw_mask == 0 {
                    return false; // SIMD told us no HW register matched.
                }
                // Compare the OFFSET, never the materialised end: `address +
                // size` wraps for a watchpoint at the top of the address
                // space, putting the upper bound below the lower one so the
                // watchpoint matches nothing and silently never fires — the
                // worst failure mode a watchpoint has. `saturating_add` would
                // still lose the last byte to the exclusive bound.
                w.enabled
                    && access_address >= w.address
                    && access_address - w.address < u64::from(w.size)
            })
            .map(|w| w.id)?;

        let wp = self.watchpoints.get_mut(&id)?;
        let old_value = wp.last_value;
        if let Some(v) = current_value {
            wp.last_value = Some(v);
        }

        let condition_matched = wp.should_stop(current_value, regs);
        // A one-shot may only be spent on a condition that was actually
        // evaluated. With the value unreadable, a value-dependent condition is
        // reported as "stop" so the user sees it, but consuming the watchpoint
        // on that basis would destroy it for a match nobody verified.
        let needs_value = matches!(
            wp.condition,
            Some(WatchpointCondition::ValueEquals { .. } |
WatchpointCondition::ValueChangesTo { .. } | WatchpointCondition::AnyChange)
        );
        let missing_register = match &wp.condition {
            Some(WatchpointCondition::RegisterEquals { name, .. }) => !regs.contains_key(name),
            _ => false,
        };
        let condition_was_evaluable =
            (current_value.is_some() || !needs_value) && !missing_register;

        wp.hit_count += 1;
        let hit_count = wp.hit_count;
        let one_shot = wp.one_shot;

        let hit = WatchpointHit {
            watchpoint_id: id,
            access_address,
            pc,
            was_write,
            new_value: current_value,
            old_value,
            condition_matched,
            hit_count,
        };

        // Remove one-shot watchpoints after first condition-matched stop.
        if one_shot && condition_matched && condition_was_evaluable {
            let _ = self.remove(id);
        }

        Some(hit)
    }

    // ── Queries ───────────────────────────────────────────────────────────────

    /// Return a reference to a watchpoint by ID.
    #[must_use]
    pub fn get(&self, id: u64) -> Option<&Watchpoint> {
        self.watchpoints.get(&id)
    }

    /// Return all watchpoints.
    #[must_use]
    pub fn all(&self) -> Vec<&Watchpoint> {
        let mut v: Vec<&Watchpoint> = self.watchpoints.values().collect();
        v.sort_by_key(|w| w.id);
        v
    }

    /// Return only enabled watchpoints.
    #[must_use]
    pub fn enabled(&self) -> Vec<&Watchpoint> {
        self.all().into_iter().filter(|w| w.enabled).collect()
    }

    /// Return only hardware watchpoints.
    #[must_use]
    pub fn hardware_watchpoints(&self) -> Vec<&Watchpoint> {
        self.all()
            .into_iter()
            .filter(|w| matches!(w.implementation, WatchpointImpl::Hardware { .. }))
            .collect()
    }

    /// Return only software watchpoints.
    #[must_use]
    pub fn software_watchpoints(&self) -> Vec<&Watchpoint> {
        self.all()
            .into_iter()
            .filter(|w| matches!(w.implementation, WatchpointImpl::SoftwarePageProtect { .. }))
            .collect()
    }

    /// Current DR7 value for x86 (to write to the debug registers via ptrace).
    #[must_use]
    pub const fn x86_dr7(&self) -> u64 {
        self.dr7.value
    }

    /// Current addresses for DR0–DR3 (x86), or DBGWVR0–DBGWVR3 (ARM64).
    ///
    /// Returns a 4-element array; entries for unused slots are `0`.
    #[must_use]
    pub fn hw_register_addresses(&self) -> [u64; 4] {
        // DR0-DR3 take the exact address. DBGWVR does not: its low three bits
        // are RES0, and the bytes actually watched inside the aligned
        // doubleword are chosen by DBGWCR.BAS. One accessor, two register
        // contracts - returning the raw address for both armed ARM64
        // watchpoints over the wrong location.
        let align = matches!(self.arch, TargetArch::Arm64 | TargetArch::Arm32);
        let mut addrs = [0u64; 4];
        for wp in self.watchpoints.values() {
            if let WatchpointImpl::Hardware { reg_index } = wp.implementation && (reg_index as usize) < 4 {
                addrs[reg_index as usize] = if align { wp.address & !7 } else { wp.address };
            }
        }
        addrs
    }

    /// Current DBGWCR values for ARM64, one per hardware slot.
    ///
    /// The counterpart of [`Self::x86_dr7`]. Unused slots read back as 0
    /// (disabled). Pair each entry with the matching
    /// [`Self::hw_register_addresses`] element, which is the DBGWVR value.
    #[must_use]
    pub const fn arm64_dbgwcr(&self) -> [u32; 4] {
        [
            self.dbgwcr[0].value,
            self.dbgwcr[1].value,
            self.dbgwcr[2].value,
            self.dbgwcr[3].value,
        ]
    }

    /// Number of hardware watchpoint slots still available.
    #[must_use]
    pub fn available_hw_slots(&self) -> u8 {
        u8::try_from(self.hw_regs.free_count()).unwrap_or(u8::MAX)
    }

    /// Total number of registered watchpoints (enabled + disabled).
    #[must_use]
    pub fn count(&self) -> usize {
        self.watchpoints.len()
    }

    /// Clear all watchpoints (e.g. on process detach).
    pub fn clear(&mut self) {
        self.watchpoints.clear();
        self.hw_regs = HwRegisterFile::default();
        self.dr7 = X86Dr7Builder::default();
        self.dbgwcr = Default::default();
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Thread-safe wrapper
// ─────────────────────────────────────────────────────────────────────────────

/// A thread-safe wrapper around [`WatchpointEngine`].
#[derive(Clone)]
pub struct SharedWatchpointEngine(Arc<RwLock<WatchpointEngine>>);

impl SharedWatchpointEngine {
    #[must_use]
    pub fn new(arch: TargetArch) -> Self {
        Self(Arc::new(RwLock::new(WatchpointEngine::new(arch))))
    }

    /// # Errors
    ///
    /// Returns `WatchpointError` if the address is already watched or allocation fails.
    pub fn add(
        &self,
        address: u64,
        size: u8,
        watch_type: WatchpointType,
        condition: Option<WatchpointCondition>,
        one_shot: bool,
        label: Option<String>,
    ) -> Result<u64, WatchpointError> {
        self.0.write().add(address, size, watch_type, condition, one_shot, label)
    }

    /// # Errors
    ///
    /// Returns `WatchpointError::NotFound` if no watchpoint has the given ID.
    pub fn remove(&self, id: u64) -> Result<Watchpoint, WatchpointError> {
        self.0.write().remove(id)
    }

    /// # Errors
    ///
    /// Returns `WatchpointError::NotFound` if no watchpoint has the given ID.
    pub fn set_enabled(&self, id: u64, enabled: bool) -> Result<(), WatchpointError> {
        self.0.write().set_enabled(id, enabled)
    }

    #[must_use]
    pub fn process_hit(
        &self,
        access_address: u64,
        pc: u64,
        was_write: bool,
        current_value: Option<u64>,
        regs: &HashMap<String, u64>,
    ) -> Option<WatchpointHit> {
        self.0.write().process_hit(access_address, pc, was_write, current_value, regs)
    }

    #[must_use]
    pub fn all_watchpoints(&self) -> Vec<Watchpoint> {
        self.0.read().all().into_iter().cloned().collect()
    }

    #[must_use]
    pub fn x86_dr7(&self) -> u64 {
        self.0.read().x86_dr7()
    }

    #[must_use]
    pub fn hw_register_addresses(&self) -> [u64; 4] {
        self.0.read().hw_register_addresses()
    }

    #[must_use]
    pub fn available_hw_slots(&self) -> u8 {
        self.0.read().available_hw_slots()
    }

    #[must_use]
    pub fn count(&self) -> usize {
        self.0.read().count()
    }

    pub fn clear(&self) {
        self.0.write().clear();
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Type-aware data breakpoints (Tier 1, item 2 of the enhancement plan)
// ─────────────────────────────────────────────────────────────────────────────
//
// Extends the engine to accept a struct type + field path (`"Foo.bar.baz"`)
// instead of a raw address, resolving the byte offset via a caller-supplied
// [`TypeLayout`] (built from DWARF/CodeView type info upstream — this module
// stays parser-agnostic and only needs a name → (offset, size) map per type).
// Also supports "break on the Nth allocation of type T" by pairing a
// [`TypeLayout`]'s `alloc_size` with the heap chunk enumeration already
// produced by [`crate::memory_layout_view`].

/// Errors specific to type-aware watchpoint resolution.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum TypeWatchError {
    #[error("unknown type: {0}")]
    UnknownType(String),
    #[error("unknown field '{1}' on type '{0}'")]
    UnknownField(String, String),
    #[error("empty field path")]
    EmptyPath,
    #[error("not enough live allocations of type '{0}': wanted #{1}, found {2}")]
    AllocationNotFound(String, usize, usize),
}

/// A single field within a [`TypeLayout`]: byte offset from the struct base
/// and size in bytes. For a nested struct field, `nested` names the type to
/// recurse into to resolve the remainder of a dotted field path.
#[derive(Debug, Clone)]
pub struct FieldLayout {
    pub offset: u64,
    pub size: u8,
    /// If this field is itself a struct, the name of its [`TypeLayout`] in
    /// the owning [`TypeRegistry`], so `"outer.inner.leaf"` paths resolve.
    pub nested: Option<String>,
}

/// The offset/size layout of one struct/class type, keyed by field name.
///
/// Callers build this from DWARF (`rustre-symbols`) or `CodeView`
/// (`crate::codeview`) type records; this module has no parser dependency.
#[derive(Debug, Clone, Default)]
pub struct TypeLayout {
    /// Total size of one instance, in bytes — used for Nth-allocation matching.
    pub alloc_size: u64,
    pub fields: HashMap<String, FieldLayout>,
}

impl TypeLayout {
    #[must_use]
    pub fn new(alloc_size: u64) -> Self {
        Self { alloc_size, fields: HashMap::new() }
    }

    #[must_use]
    pub fn with_field(mut self, name: impl Into<String>, offset: u64, size: u8) -> Self {
        self.fields.insert(name.into(), FieldLayout { offset, size, nested: None });
        self
    }

    #[must_use]
    pub fn with_nested_field(mut self, name: impl Into<String>, offset: u64, size: u8, nested_type: impl Into<String>) -> Self {
        self.fields.insert(name.into(), FieldLayout { offset, size, nested: Some(nested_type.into()) });
        self
    }
}

/// A collection of named [`TypeLayout`]s, resolving dotted field paths across
/// nested structs.
#[derive(Debug, Clone, Default)]
pub struct TypeRegistry {
    types: HashMap<String, TypeLayout>,
}

impl TypeRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self, type_name: impl Into<String>, layout: TypeLayout) {
        self.types.insert(type_name.into(), layout);
    }

    #[must_use]
    pub fn get(&self, type_name: &str) -> Option<&TypeLayout> {
        self.types.get(type_name)
    }

    /// Resolve a dotted field path (e.g. `"pos.x"`) starting from `type_name`,
    /// returning the cumulative byte offset from the struct base and the leaf
    /// field's size.
    ///
    /// # Errors
    /// Returns [`TypeWatchError::UnknownType`]/[`TypeWatchError::UnknownField`]
    /// if any component of the path cannot be resolved, or
    /// [`TypeWatchError::EmptyPath`] if `field_path` is empty.
    pub fn resolve_field(&self, type_name: &str, field_path: &str) -> Result<(u64, u8), TypeWatchError> {
        let parts: Vec<&str> = field_path.split('.').filter(|s| !s.is_empty()).collect();
        if parts.is_empty() {
            return Err(TypeWatchError::EmptyPath);
        }

        let mut cur_type = type_name.to_owned();
        let mut cumulative_offset = 0u64;
        let mut leaf_size = 0u8;

        for (i, part) in parts.iter().enumerate() {
            let layout = self.types.get(&cur_type)
                .ok_or_else(|| TypeWatchError::UnknownType(cur_type.clone()))?;
            let field = layout.fields.get(*part)
                .ok_or_else(|| TypeWatchError::UnknownField(cur_type.clone(), (*part).to_owned()))?;
            cumulative_offset += field.offset;
            leaf_size = field.size;

            let is_last = i + 1 == parts.len();
            if !is_last {
                let nested = field.nested.clone()
                    .ok_or_else(|| TypeWatchError::UnknownField(cur_type.clone(), (*part).to_owned()))?;
                cur_type = nested;
            }
        }

        Ok((cumulative_offset, leaf_size))
    }
}

/// Given a base address and a dotted field path resolved against `registry`,
/// compute the absolute watch address.
///
/// # Errors
/// Propagates [`TypeWatchError`] from [`TypeRegistry::resolve_field`].
pub fn resolve_field_address(
    registry: &TypeRegistry,
    type_name: &str,
    base_address: u64,
    field_path: &str,
) -> Result<(u64, u8), TypeWatchError> {
    let (offset, size) = registry.resolve_field(type_name, field_path)?;
    Ok((base_address.saturating_add(offset), size))
}

/// Find the Nth (1-based) live heap allocation whose user size matches
/// `type_name`'s `alloc_size` in `registry`, returning its user data address.
///
/// Pairs with [`crate::memory_layout_view::HeapLayout`]'s chunk enumeration:
/// callers pass the chunks from a live heap walk, and this scans them in
/// address order, counting only chunks that are live (`state ==
/// ChunkState::Allocated`, checked by the caller via `is_live`) and whose
/// `user_size` equals the type's `alloc_size`.
///
/// # Errors
/// Returns [`TypeWatchError::UnknownType`] if `type_name` isn't registered,
/// or [`TypeWatchError::AllocationNotFound`] if fewer than `n` matching live
/// allocations exist.
pub fn find_nth_allocation<'a, I>(
    registry: &TypeRegistry,
    type_name: &str,
    n: usize,
    live_chunks: I,
) -> Result<u64, TypeWatchError>
where
    I: IntoIterator<Item = (u64, u64, bool)>, // (user_addr, user_size, is_live)
{
    let layout = registry.get(type_name)
        .ok_or_else(|| TypeWatchError::UnknownType(type_name.to_owned()))?;
    let mut found = 0usize;
    for (user_addr, user_size, is_live) in live_chunks {
        if is_live && user_size == layout.alloc_size {
            found += 1;
            if found == n {
                return Ok(user_addr);
            }
        }
    }
    Err(TypeWatchError::AllocationNotFound(type_name.to_owned(), n, found))
}

impl WatchpointEngine {
    /// Add a watchpoint on `type_name.field_path` at instance `base_address`,
    /// resolving the offset/size via `registry` instead of requiring the
    /// caller to compute a raw address.
    ///
    /// # Errors
    /// Returns [`TypeWatchError`] if the field path doesn't resolve, or
    /// wraps a [`WatchpointError`] if watchpoint registration fails (e.g. no
    /// hardware register free and size unsupported).
    pub fn add_type_field_watchpoint(
        &mut self,
        registry: &TypeRegistry,
        type_name: &str,
        base_address: u64,
        field_path: &str,
        watch_type: WatchpointType,
        condition: Option<WatchpointCondition>,
        one_shot: bool,
    ) -> Result<u64, TypeFieldWatchError> {
        let (address, size) = resolve_field_address(registry, type_name, base_address, field_path)
            .map_err(TypeFieldWatchError::Type)?;
        let label = format!("{type_name}.{field_path}");
        self.add(address, size, watch_type, condition, one_shot, Some(label))
            .map_err(TypeFieldWatchError::Watchpoint)
    }
}

/// Combined error for [`WatchpointEngine::add_type_field_watchpoint`].
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum TypeFieldWatchError {
    #[error(transparent)]
    Type(#[from] TypeWatchError),
    #[error(transparent)]
    Watchpoint(#[from] WatchpointError),
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    /// `BAS` selects bytes inside a doubleword, and the architecture defines
    /// it only for NATURALLY ALIGNED regions.
    ///
    /// The length check alone accepts a four-byte watch at offset 2 —
    /// `BAS = 0x3C`, eight contiguous bits — which is CONSTRAINED UNPREDICTABLE
    /// on `ARMv8`: in practice a watchpoint that may fire on the wrong access, or
    /// not at all. Unreachable through `add()`, which validates alignment
    /// first, but `set_bas` is public and the guarantee belongs where the value
    /// is built.
    #[test]
    fn bas_accepts_only_naturally_aligned_byte_selections() {
        // Every legal placement of every legal size.
        for size in [1u8, 2, 4, 8] {
            let mut offset = 0u8;
            while offset + size <= 8 {
                let mut ctl = Arm64DbgwcrBuilder::default();
                let ok = ctl.set_bas(offset, size);
                assert_eq!(
                    ok,
                    offset.is_multiple_of(size),
                    "size {size} at offset {offset}: only naturally aligned selections are architecturally defined"
                );
                offset += 1;
            }
        }
        // And the one that used to slip through.
        let mut ctl = Arm64DbgwcrBuilder::default();
        assert!(!ctl.set_bas(2, 4), "a 4-byte watch at offset 2 straddles the aligned region");
    }

    /// A request the debug registers cannot express must not consume one.
    ///
    /// `add` picks hardware only when the size and alignment fit the registers,
    /// and falls back to a software page-protect watchpoint otherwise. The
    /// property worth pinning is that the rejected-for-hardware path leaves the
    /// four slots exactly as it found them — a misaligned request that quietly
    /// ate a slot would starve the next legitimate one.
    ///
    /// (The `set_bas` failure branch inside the hardware path now frees its slot
    /// and returns an error too. That branch is not reachable from here —
    /// `add` validates alignment before allocating — but a slot allocated for a
    /// configuration that then fails must be given back wherever that happens.)
    #[test]
    fn a_request_the_registers_cannot_express_does_not_consume_a_slot() {
        let mut e = WatchpointEngine::new(TargetArch::Arm64);
        let free_before = e.available_hw_slots();

        // Misaligned for its size: cannot be a hardware watchpoint.
        let id = e
            .add(0x1002, 4, WatchpointType::Write, None, false, None)
            .expect("a misaligned request falls back to software rather than failing");
        assert_eq!(
            e.available_hw_slots(),
            free_before,
            "a request that could not use the debug registers still consumed one of the four slots"
        );
        assert_eq!(
            e.hardware_watchpoints().len(),
            0,
            "it must not be recorded as a hardware watchpoint either"
        );
        assert_eq!(e.get(id).map(|w| w.address), Some(0x1002));
    }

    /// The two ARM64 control-word encoders must agree, and neither may widen.
    ///
    /// The twin of the DR7 differential test. `Arm64DbgwcrBuilder` here and
    /// `crate::arm64_encode_watchpoint_wcr` (used by the macOS backend) program
    /// the same `DBGWCR`, and they disagreed on two things that both end in
    /// silence:
    ///
    /// * `set_bas` folded every unrecognised size into `0xff` — all EIGHT bytes
    ///   of the doubleword. A 3-byte request became an 8-byte watch, so a write
    ///   to the NEIGHBOURING field reported as a hit on the watched one.
    /// * the builder never set `PAC`, leaving it `0b00`. A watchpoint with
    ///   `PAC = 0` arms cleanly and can never fire, because no user-mode access
    ///   matches it — indistinguishable from "the program never touched it".
    ///
    /// Both live on the platform this host cannot execute, which is exactly where
    /// a silent defect survives longest.
    #[test]
    fn both_arm64_control_word_encoders_agree_and_neither_widens_the_watch() {
        use crate::BreakpointKind;

        for (kind, _) in [
            (BreakpointKind::DataWrite, 0b10u8),
            (BreakpointKind::DataRead, 0b01),
            (BreakpointKind::DataReadWrite, 0b11),
        ] {
            for (addr, size) in [(0x1000u64, 1u8), (0x1002, 2), (0x1004, 4), (0x1000, 8)] {
                let expected = crate::arm64_encode_watchpoint_wcr(addr, kind, size)
                    .expect("the backend encoder must accept an aligned supported size");
                let mut b = Arm64DbgwcrBuilder::default();
                assert!(b.apply_watchpoint(addr, kind, size), "the builder refused a valid request");
                assert_eq!(
                    u64::from(b.value),
                    expected,
                    "the two DBGWCR encoders disagree for {kind:?} {size} bytes at {addr:#x}"
                );
                assert_eq!(
                    (b.value >> 1) & 0b11,
                    0b10,
                    "PAC is not EL0: this watchpoint is armed and can never fire"
                );
            }
        }

        // A size the field cannot express must be refused, NOT widened to the
        // whole doubleword.
        for size in [3u8, 5, 6, 7, 16] {
            let mut b = Arm64DbgwcrBuilder::default();
            assert!(
                !b.set_bas(0, size),
                "BAS accepted a {size}-byte watch and widened it to the whole doubleword"
            );
            assert_eq!(b.value, 0, "a refused request must leave the control word untouched");
        }

        // And a region that straddles the doubleword has no mask at all.
        let mut b = Arm64DbgwcrBuilder::default();
        assert!(
            !b.set_bas(6, 4),
            "BAS accepted a 4-byte watch at offset 6, which runs past the doubleword it indexes"
        );
    }
    /// The two DR7 encoders in this crate must agree, bit for bit.
    ///
    /// The same register is programmed by two independent pieces of code:
    /// `X86Dr7Builder` here, and `crate::x86_encode_watchpoint_dr7`, which is what
    /// the three OS backends actually call. Two implementations of one hardware
    /// register is a standing invitation to divergence, and only one of them was
    /// ever checked against a live target.
    ///
    /// They DID diverge, on the case that matters most: an unsupported size. The
    /// encoder refuses it; the builder folded it into `0b00` — ONE BYTE — so a
    /// request to watch 3 or 16 bytes produced a watchpoint over the first byte
    /// and said nothing. A write to the second byte then goes unnoticed while the
    /// caller believes the region is covered.
    #[test]
    fn both_dr7_encoders_agree_and_both_refuse_what_the_hardware_cannot_express() {
        use crate::BreakpointKind;

        for slot in 0u8..4 {
            for (kind, rw) in [
                (BreakpointKind::DataWrite, 0b01u8),
                (BreakpointKind::DataReadWrite, 0b11),
            ] {
                for size in [1u8, 2, 4, 8] {
                    // Aligned, so the encoder's alignment rule is satisfied and
                    // only the ENCODING is under test.
                    let addr = 0x1000u64;
                    let expected = crate::x86_encode_watchpoint_dr7(0, slot, addr, kind, size)
                        .expect("the backend encoder must accept a supported size");

                    let mut builder = X86Dr7Builder::default();
                    assert!(
                        builder.apply_watchpoint(slot, rw, size, true),
                        "the builder refused a size the hardware supports"
                    );
                    assert_eq!(
                        builder.value,
                        expected,
                        "the two DR7 encoders disagree for slot {slot}, kind {kind:?}, size {size}"
                    );
                }
            }
        }

        // The sizes the hardware cannot express: BOTH must refuse.
        for size in [3u8, 5, 6, 7, 16] {
            assert!(
                crate::x86_encode_watchpoint_dr7(0, 0, 0x1000, BreakpointKind::DataWrite, size)
                    .is_err(),
                "the backend encoder accepted a {size}-byte watchpoint"
            );
            let mut builder = X86Dr7Builder::default();
            assert!(
                !builder.apply_watchpoint(0, 0b01, size, true),
                "the builder accepted a {size}-byte watchpoint and silently narrowed it to one byte"
            );
            assert_eq!(
                builder.value & 1,
                0,
                "the builder left slot 0 ENABLED after refusing the size: a watchpoint of the wrong width is armed"
            );
        }
    }
    use super::*;

    /// A watchpoint on the last word of the address space must still fire.
    ///
    /// The coverage test was `access < w.address + size`, and that `+` wraps to
    /// 0 for `address = u64::MAX - 7`: the upper bound ends up BELOW the lower
    /// one, no access can ever satisfy both, and the watchpoint silently never
    /// reports a hit. Kernel-space addresses live at exactly this end of the
    /// range. (In a debug build the same `+` panics instead; release, which is
    /// how this crate is tested and shipped, wraps quietly.)
    /// A register that is not available must not be reported as "did not match".
    ///
    /// `RegisterEquals` compared `regs.get(name).unwrap_or(u64::MAX)`, so a
    /// register the backend did not supply — or a misspelled name — produced a
    /// comparison against a fabricated `u64::MAX`. The hit then came back with
    /// `condition_matched: false`, which is a specific claim: *the register
    /// holds something other than what you asked for*. It holds nothing that
    /// was ever read. The user concludes the value is wrong and goes looking at
    /// the program, when the answer is that the name is unavailable.
    ///
    /// Note the one-shot survives either way here — `u64::MAX == 42` is false,
    /// so nothing was consumed. Asserting on survival would have passed against
    /// the unfixed code; the discriminating observable is `condition_matched`.
    #[test]
    fn a_missing_register_is_not_reported_as_a_failed_comparison() {
        let mut engine = WatchpointEngine::new(TargetArch::X86_64);
        engine
            .add(
                0x5000,
                8,
                WatchpointType::Write,
                Some(WatchpointCondition::RegisterEquals {
                    name: "rax".to_string(),
                    value: 42,
                }),
                false,
                None,
            )
            .unwrap();

        // No registers at all: `rax` is absent, not zero and not `u64::MAX`.
        let hit = engine
            .process_hit(0x5000, 0x1000, true, Some(7), &HashMap::new())
            .expect("the access must still be reported");
        assert!(
            hit.condition_matched,
            "an unavailable register was reported as a comparison that failed"
        );

        // With the register present and DIFFERENT, the comparison is real and
        // must be reported as not matching — otherwise the fix would just have
        // made every register condition always true.
        let mut regs = HashMap::new();
        regs.insert("rax".to_string(), 7u64);
        let hit = engine
            .process_hit(0x5000, 0x1000, true, Some(7), &regs)
            .expect("reported");
        assert!(
            !hit.condition_matched,
            "a real comparison against a different value must still not match"
        );
    }

    /// The module doc and the code must agree about ARM64 control words.
    ///
    /// The doc used to say the engine "builds ... the ARM64 DBGWCR value". It
    /// does not: `WatchpointEngine` holds a `dr7` field and no ARM64
    /// counterpart, and never calls [`Arm64DbgwcrBuilder`]. Someone wiring an
    /// ARM64 backend would have gone looking for a control word that is never
    /// computed.
    ///
    /// This guard pins the pair. If the engine ever DOES build the value, the
    /// note above stops being true and this fails, which is the point: the two
    /// may change together or not at all.
    #[test]
    fn the_arm64_control_word_claim_matches_the_code() {
        let src = include_str!("watchpoint_engine.rs");
        let module_doc: String = src
            .lines()
            .take_while(|l| l.starts_with("//!"))
            .collect::<Vec<_>>()
            .join("
");
        // Production slice only: the tests below legitimately exercise the
        // builder in isolation.
        let production = src.split("#[cfg(test)]").next().unwrap_or(src);
        let engine_body = production
            .split("pub struct WatchpointEngine")
            .nth(1)
            .expect("the engine type must exist");

        let engine_uses_it = engine_body.contains("Arm64DbgwcrBuilder");
        let doc_says_not_wired = module_doc.contains("ARM64 control words are NOT wired in");
        assert_eq!(
            engine_uses_it, !doc_says_not_wired,
            "the module doc and the engine disagree about ARM64 control words              (engine uses builder: {engine_uses_it}, doc says not wired: {doc_says_not_wired})"
        );
    }

    /// An unreadable value must not be treated as the value zero.
    ///
    /// `process_hit` passed `current_value.unwrap_or(0)` into the condition, so
    /// memory that could NOT be read arrived as a genuine `0`. With
    /// `ValueEquals { expected: 0 }` the condition then "matched" a value nobody
    /// ever read — and because a matched one-shot is removed, the watchpoint was
    /// spent and gone: it can never fire again, and nothing in the output says
    /// why. A watchpoint that silently deletes itself is the worst shape this
    /// bug could take.
    ///
    /// After the fix the hit is still reported (an unverifiable condition stops
    /// rather than hides), but the one-shot survives, because consuming it must
    /// be justified by a condition that was actually evaluated.
    #[test]
    fn an_unreadable_value_does_not_consume_a_one_shot_watchpoint() {
        let mut engine = WatchpointEngine::new(TargetArch::X86_64);
        let id = engine
            .add(
                0x4000,
                8,
                WatchpointType::Write,
                Some(WatchpointCondition::ValueEquals { expected: 0 }),
                true, // one-shot
                None,
            )
            .unwrap();

        // The debugger could not read the watched memory: `None`, not `Some(0)`.
        let hit = engine.process_hit(0x4000, 0x1000, true, None, &HashMap::new());
        assert!(hit.is_some(), "the access must still be reported");
        assert!(
            engine.get(id).is_some(),
            "the one-shot was consumed by a condition that was never evaluated"
        );

        // And a genuine read of 0 does consume it, so the guard did not simply
        // disable one-shot behaviour.
        let hit = engine.process_hit(0x4000, 0x1000, true, Some(0), &HashMap::new());
        assert!(hit.is_some());
        assert!(
            engine.get(id).is_none(),
            "a real match must still spend the one-shot"
        );
    }

    #[test]
    fn a_watchpoint_at_the_top_of_the_address_space_still_fires() {
        let mut engine = WatchpointEngine::new(TargetArch::X86_64);
        let top = u64::MAX - 7; // 8-aligned, so it takes the hardware path
        let id = engine.add(top, 8, WatchpointType::Write, None, false, None).unwrap();
        let hit = engine.process_hit(top, 0x1000, true, Some(0xdead), &HashMap::new());
        assert!(
            hit.is_some(),
            "watchpoint at {top:#x} did not fire — the range check wrapped"
        );
        assert_eq!(hit.unwrap().watchpoint_id, id);
    }

    #[test]
    fn test_add_hardware_watchpoint() {
        let mut engine = WatchpointEngine::new(TargetArch::X86_64);
        let id = engine
            .add(0x1000, 8, WatchpointType::Write, None, false, None)
            .unwrap();
        assert_eq!(id, 1);
        assert_eq!(engine.available_hw_slots(), 3);
        let wp = engine.get(id).unwrap();
        assert!(matches!(wp.implementation, WatchpointImpl::Hardware { reg_index: 0 }));
    }

    #[test]
    fn test_hw_limit_fallback_to_software() {
        let mut engine = WatchpointEngine::new(TargetArch::X86_64);
        for i in 0u64..4 {
            engine
                .add(0x1000 + i * 8, 8, WatchpointType::Write, None, false, None)
                .unwrap();
        }
        // 5th watchpoint: no hardware slot — must use software.
        let id = engine.add(0x2000, 8, WatchpointType::Write, None, false, None).unwrap();
        let wp = engine.get(id).unwrap();
        assert!(matches!(wp.implementation, WatchpointImpl::SoftwarePageProtect { .. }));
    }

    #[test]
    fn test_condition_value_equals() {
        let mut engine = WatchpointEngine::new(TargetArch::X86_64);
        let _id = engine
            .add(
                0x4000,
                8,
                WatchpointType::Write,
                Some(WatchpointCondition::ValueEquals { expected: 0xdead_beef }),
                false,
                None,
            )
            .unwrap();
        let regs = HashMap::new();
        let hit = engine.process_hit(0x4000, 0x0040_1000, true, Some(0xdead_beef), &regs).unwrap();
        assert!(hit.condition_matched);
        let hit2 = engine.process_hit(0x4000, 0x0040_1004, true, Some(0x1234), &regs).unwrap();
        assert!(!hit2.condition_matched);
    }

    #[test]
    fn test_one_shot_removed_after_hit() {
        let mut engine = WatchpointEngine::new(TargetArch::X86_64);
        let id = engine.add(0x8000, 4, WatchpointType::Write, None, true, None).unwrap();
        let regs = HashMap::new();
        let hit = engine.process_hit(0x8000, 0x0040_1000, true, Some(1), &regs).unwrap();
        assert!(hit.condition_matched);
        // After one-shot hit the watchpoint should be gone.
        assert!(engine.get(id).is_none());
        assert_eq!(engine.count(), 0);
    }

    #[test]
    fn test_dr7_enable_disable() {
        let mut builder = X86Dr7Builder::default();
        builder.apply_watchpoint(0, 0b01, 4, true);
        assert_ne!(builder.value, 0);
        builder.disable_local(0);
        assert_eq!(builder.value & 1, 0);
    }

    /// The engine now produces a usable DBGWCR, not just an allocated slot.
    ///
    /// Before this, an ARM64 target got a slot and bookkeeping but no control
    /// word at all: `Arm64DbgwcrBuilder` existed, was correct, and was never
    /// called. A backend programming the registers itself had nothing to write,
    /// so hardware watchpoints could not work on ARM64 — i.e. on Apple Silicon,
    /// which is what macOS means today.
    #[test]
    fn arm64_hardware_watchpoints_produce_an_armed_control_word() {
        let mut e = WatchpointEngine::new(TargetArch::Arm64);
        let id = e.add(0x1004, 4, WatchpointType::Write, None, false, None).expect("hw slot");

        let ctl = e.arm64_dbgwcr()[0];
        assert_eq!(ctl & 1, 1, "EN must be set for an enabled watchpoint");
        assert_eq!(
            (ctl >> 3) & 0b11,
            u32::from(WatchpointType::Write.arm64_dbgwcr_lsc()),
            "LSC must describe the access type asked for"
        );
        // 4 bytes at offset 4 inside the aligned doubleword -> BAS 0b1111_0000.
        assert_eq!((ctl >> 5) & 0xFF, 0xF0, "BAS must select the upper four bytes");

        // Disabling clears EN but keeps the slot programmed...
        e.set_enabled(id, false).expect("known id");
        assert_eq!(e.arm64_dbgwcr()[0] & 1, 0, "EN must clear on disable");
        e.set_enabled(id, true).expect("known id");
        assert_eq!(e.arm64_dbgwcr()[0] & 1, 1, "EN must come back on re-enable");

        // ...and removing it releases the register entirely.
        e.remove(id).expect("known id");
        assert_eq!(e.arm64_dbgwcr()[0], 0, "a freed slot must not stay armed");

        // The x86 path is untouched: no DBGWCR, DR7 as before.
        let mut x = WatchpointEngine::new(TargetArch::X86_64);
        x.add(0x2000, 4, WatchpointType::Write, None, false, None).expect("hw slot");
        assert_eq!(x.arm64_dbgwcr(), [0; 4], "x86 targets must not program DBGWCR");
        assert_eq!(x.x86_dr7() & 1, 1, "DR7 local-enable for slot 0 still set");
    }

    /// On ARM64 the value handed to DBGWVR must be 8-byte aligned.
    ///
    /// `hw_register_addresses` documents itself as returning "DR0-DR3 (x86), or
    /// DBGWVR0-DBGWVR3 (ARM64)", but returned the raw watched address for both.
    /// DR0-DR3 do take the exact address; DBGWVR does not — its low three bits
    /// are RES0, and the byte actually watched inside the aligned doubleword is
    /// chosen by DBGWCR.BAS. Writing an unaligned value there programs the
    /// wrong register content, so a backend that trusts this accessor arms a
    /// watchpoint that does not cover what the user asked for.
    ///
    /// The x86 side must keep receiving the exact address: same accessor, two
    /// contracts, and that is exactly why it was wrong for one of them.
    #[test]
    fn arm64_watch_registers_are_aligned_but_x86_ones_are_exact() {
        // 4 bytes at 0x1004: legal on both (aligned to its own size), and it
        // sits in the SECOND half of the 8-byte word at 0x1000.
        let mut arm = WatchpointEngine::new(TargetArch::Arm64);
        arm.add(0x1004, 4, WatchpointType::Write, None, false, None).expect("hw slot");
        assert_eq!(
            arm.hw_register_addresses()[0],
            0x1000,
            "DBGWVR takes the 8-byte-aligned base; the byte selection lives in BAS"
        );

        let mut x86 = WatchpointEngine::new(TargetArch::X86_64);
        x86.add(0x1004, 4, WatchpointType::Write, None, false, None).expect("hw slot");
        assert_eq!(
            x86.hw_register_addresses()[0],
            0x1004,
            "DR0-DR3 hold the exact address, not an aligned one"
        );
    }

    #[test]
    fn test_arm64_dbgwcr_builder() {
        let mut b = Arm64DbgwcrBuilder::default();
        b.enable();
        b.set_lsc(WatchpointType::Write.arm64_dbgwcr_lsc());
        b.set_bas(0, 8);
        assert_eq!(b.value & 1, 1); // EN bit
    }

    #[test]
    fn test_remove_watchpoint() {
        let mut engine = WatchpointEngine::new(TargetArch::X86_64);
        let id = engine.add(0x1000, 4, WatchpointType::Read, None, false, None).unwrap();
        let removed = engine.remove(id).unwrap();
        assert_eq!(removed.id, id);
        assert_eq!(engine.count(), 0);
        assert_eq!(engine.available_hw_slots(), 4);
    }

    // ── Type-aware data breakpoints ─────────────────────────────────────────

    fn make_registry() -> TypeRegistry {
        // struct Vec3 { x: i32 (0), y: i32 (4), z: i32 (8) }  size=12
        // struct Entity { id: u32 (0), pos: Vec3 (4), hp: i32 (16) } size=20
        let mut reg = TypeRegistry::new();
        reg.register(
            "Vec3",
            TypeLayout::new(12).with_field("x", 0, 4).with_field("y", 4, 4).with_field("z", 8, 4),
        );
        reg.register(
            "Entity",
            TypeLayout::new(20)
                .with_field("id", 0, 4)
                .with_nested_field("pos", 4, 12, "Vec3")
                .with_field("hp", 16, 4),
        );
        reg
    }

    #[test]
    fn type_registry_resolves_top_level_field() {
        let reg = make_registry();
        let (off, size) = reg.resolve_field("Entity", "hp").unwrap();
        assert_eq!(off, 16);
        assert_eq!(size, 4);
    }

    #[test]
    fn type_registry_resolves_nested_field() {
        let reg = make_registry();
        let (off, size) = reg.resolve_field("Entity", "pos.y").unwrap();
        assert_eq!(off, 4 + 4); // pos offset + y offset
        assert_eq!(size, 4);
    }

    #[test]
    fn type_registry_unknown_type() {
        let reg = make_registry();
        assert_eq!(
            reg.resolve_field("Nonexistent", "x"),
            Err(TypeWatchError::UnknownType("Nonexistent".into()))
        );
    }

    #[test]
    fn type_registry_unknown_field() {
        let reg = make_registry();
        assert_eq!(
            reg.resolve_field("Entity", "nope"),
            Err(TypeWatchError::UnknownField("Entity".into(), "nope".into()))
        );
    }

    #[test]
    fn type_registry_empty_path() {
        let reg = make_registry();
        assert_eq!(reg.resolve_field("Entity", ""), Err(TypeWatchError::EmptyPath));
    }

    #[test]
    fn type_registry_non_nested_field_used_as_nested_errors() {
        let reg = make_registry();
        // "id" is a plain u32, not a nested struct — "id.foo" must fail.
        let err = reg.resolve_field("Entity", "id.foo").unwrap_err();
        assert!(matches!(err, TypeWatchError::UnknownField(_, _)));
    }

    #[test]
    fn resolve_field_address_computes_absolute_address() {
        let reg = make_registry();
        let (addr, size) = resolve_field_address(&reg, "Entity", 0x2000, "pos.z").unwrap();
        assert_eq!(addr, 0x2000 + 4 + 8);
        assert_eq!(size, 4);
    }

    #[test]
    fn add_type_field_watchpoint_sets_up_hw_watch() {
        let reg = make_registry();
        let mut engine = WatchpointEngine::new(TargetArch::X86_64);
        let id = engine
            .add_type_field_watchpoint(&reg, "Entity", 0x2000, "hp", WatchpointType::Write, None, false)
            .unwrap();
        let wp = engine.get(id).unwrap();
        assert_eq!(wp.address, 0x2000 + 16);
        assert_eq!(wp.size, 4);
        assert_eq!(wp.label.as_deref(), Some("Entity.hp"));
    }

    #[test]
    fn add_type_field_watchpoint_propagates_unknown_field() {
        let reg = make_registry();
        let mut engine = WatchpointEngine::new(TargetArch::X86_64);
        let err = engine
            .add_type_field_watchpoint(&reg, "Entity", 0x2000, "bogus", WatchpointType::Write, None, false)
            .unwrap_err();
        assert!(matches!(err, TypeFieldWatchError::Type(TypeWatchError::UnknownField(_, _))));
    }

    #[test]
    fn find_nth_allocation_matches_by_size() {
        let reg = make_registry();
        // Three chunks: two Vec3-sized (12), one different; want the 2nd Vec3.
        let chunks = vec![
            (0x1000u64, 12u64, true),
            (0x1020u64, 20u64, true), // Entity-sized, wrong type
            (0x1040u64, 12u64, true),
            (0x1060u64, 12u64, false), // freed, must be skipped
        ];
        let addr = find_nth_allocation(&reg, "Vec3", 2, chunks).unwrap();
        assert_eq!(addr, 0x1040);
    }

    #[test]
    fn find_nth_allocation_skips_dead_chunks() {
        let reg = make_registry();
        let chunks = vec![(0x1000u64, 12u64, false), (0x2000u64, 12u64, true)];
        let addr = find_nth_allocation(&reg, "Vec3", 1, chunks).unwrap();
        assert_eq!(addr, 0x2000);
    }

    #[test]
    fn find_nth_allocation_not_found() {
        let reg = make_registry();
        let chunks = vec![(0x1000u64, 12u64, true)];
        let err = find_nth_allocation(&reg, "Vec3", 5, chunks).unwrap_err();
        assert_eq!(err, TypeWatchError::AllocationNotFound("Vec3".into(), 5, 1));
    }

    #[test]
    fn find_nth_allocation_unknown_type() {
        let reg = make_registry();
        let err = find_nth_allocation(&reg, "Ghost", 1, Vec::<(u64, u64, bool)>::new()).unwrap_err();
        assert_eq!(err, TypeWatchError::UnknownType("Ghost".into()));
    }

    // ── Opt-2: SIMD watchpoint scan tests ────────────────────────────────────

    #[test]
    fn simd_scan_match_slot_0() {
        let addrs = [0x1000u64, 0x2000, 0x3000, 0x4000];
        let mask = super::simd_scan_hw_registers_runtime(0x1000, addrs);
        assert_eq!(mask & 1, 1, "slot 0 should match");
    }

    #[test]
    fn simd_scan_match_slot_3() {
        let addrs = [0x1000u64, 0x2000, 0x3000, 0x4000];
        let mask = super::simd_scan_hw_registers_runtime(0x4000, addrs);
        assert_eq!(mask & 0b1000, 0b1000, "slot 3 should match");
    }

    #[test]
    fn simd_scan_no_match() {
        let addrs = [0x1000u64, 0x2000, 0x3000, 0x4000];
        let mask = super::simd_scan_hw_registers_runtime(0xDEAD, addrs);
        assert_eq!(mask, 0, "no slot should match");
    }

    #[test]
    fn simd_scan_all_match() {
        let addrs = [0xBEEFu64; 4];
        let mask = super::simd_scan_hw_registers_runtime(0xBEEF, addrs);
        assert_eq!(mask & 0xF, 0xF, "all slots should match");
    }

    #[test]
    fn simd_scan_multiple_matches() {
        let addrs = [0xAu64, 0xBu64, 0xAu64, 0xCu64];
        let mask = super::simd_scan_hw_registers_runtime(0xA, addrs);
        // slots 0 and 2 match
        assert_eq!(mask & 0b0101, 0b0101);
    }
}

#[cfg(test)]
mod breakpoint_kind_conversion_tests {
    use super::WatchpointType;
    use crate::BreakpointKind;

    /// The engine and the `Debugger` trait describe the same debug registers
    /// with two vocabularies. Nothing converted between them, so the MCP
    /// watchpoint tools programmed DR0-3/DR7 themselves from the engine model
    /// instead of asking the debugger — and the debugger, never told, could not
    /// list those watchpoints, re-arm them on new threads, or disarm them on
    /// detach.
    #[test]
    fn every_access_type_maps_to_the_kind_that_arms_it() {
        assert_eq!(WatchpointType::Read.as_breakpoint_kind(), BreakpointKind::DataRead);
        assert_eq!(WatchpointType::Write.as_breakpoint_kind(), BreakpointKind::DataWrite);
        assert_eq!(WatchpointType::Access.as_breakpoint_kind(), BreakpointKind::DataReadWrite);
        // An execution trap through a debug register is NOT a data watchpoint;
        // calling it one would arm the wrong R/W bits and the trap would fire
        // on data access instead of on instruction fetch.
        assert_eq!(WatchpointType::Execute.as_breakpoint_kind(), BreakpointKind::Hardware);
    }

    /// Round trip, so the two directions cannot drift apart.
    #[test]
    fn the_conversion_round_trips_for_every_access_type() {
        for wt in [
            WatchpointType::Read,
            WatchpointType::Write,
            WatchpointType::Access,
            WatchpointType::Execute,
        ] {
            assert_eq!(
                WatchpointType::from_breakpoint_kind(wt.as_breakpoint_kind()),
                Some(wt),
                "{wt} does not survive the trip through BreakpointKind"
            );
        }
    }

    /// A software breakpoint is not expressible in a debug register, and the
    /// conversion must say so rather than pick a plausible access type.
    #[test]
    fn a_software_breakpoint_has_no_access_type() {
        assert_eq!(WatchpointType::from_breakpoint_kind(BreakpointKind::Software), None);
    }
}
