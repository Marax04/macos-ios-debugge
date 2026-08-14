//! RISC-V exception and interrupt handler analysis.
//!
//! This module provides types and functions for working with RISC-V trap
//! handling:
//! - `TrapCause` — decoded exception/interrupt cause
//! - `ExceptionVector` — parsed trap vector table entry
//! - `RiscvExceptionHandler` — analyser for a machine's trap setup
//! - `mcause_decode` — decode mcause/scause into `TrapCause`

use std::collections::HashMap;
use std::fmt;

// ── Trap cause ────────────────────────────────────────────────────────────────

/// The kind of a RISC-V trap.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TrapKind {
    /// Synchronous exception originating from an instruction.
    Exception,
    /// Asynchronous interrupt.
    Interrupt,
}

impl fmt::Display for TrapKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Exception => f.write_str("Exception"),
            Self::Interrupt => f.write_str("Interrupt"),
        }
    }
}

/// Exception codes for synchronous exceptions (mcause/scause with bit63/31=0).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ExceptionCode {
    InstrAddrMisaligned,
    InstrAccessFault,
    IllegalInstruction,
    Breakpoint,
    LoadAddrMisaligned,
    LoadAccessFault,
    StoreAmoMisaligned,
    StoreAmoAccessFault,
    EcallFromU,
    EcallFromS,
    EcallFromVS,
    EcallFromM,
    InstrPageFault,
    LoadPageFault,
    StoreAmoPageFault,
    InstrGuestPageFault,
    LoadGuestPageFault,
    VirtualInstruction,
    StoreAmoGuestPageFault,
    Unknown(u64),
}

impl ExceptionCode {
    /// Decode from a raw cause code.
    #[must_use]
    pub fn from_raw(code: u64) -> Self {
        match code {
            0  => Self::InstrAddrMisaligned,
            1  => Self::InstrAccessFault,
            2  => Self::IllegalInstruction,
            3  => Self::Breakpoint,
            4  => Self::LoadAddrMisaligned,
            5  => Self::LoadAccessFault,
            6  => Self::StoreAmoMisaligned,
            7  => Self::StoreAmoAccessFault,
            8  => Self::EcallFromU,
            9  => Self::EcallFromS,
            10 => Self::EcallFromVS,
            11 => Self::EcallFromM,
            12 => Self::InstrPageFault,
            13 => Self::LoadPageFault,
            15 => Self::StoreAmoPageFault,
            20 => Self::InstrGuestPageFault,
            21 => Self::LoadGuestPageFault,
            22 => Self::VirtualInstruction,
            23 => Self::StoreAmoGuestPageFault,
            n  => Self::Unknown(n),
        }
    }

    /// Short description of this exception.
    #[must_use]
    pub fn description(self) -> &'static str {
        match self {
            Self::InstrAddrMisaligned    => "Instruction address misaligned",
            Self::InstrAccessFault       => "Instruction access fault",
            Self::IllegalInstruction     => "Illegal instruction",
            Self::Breakpoint             => "Breakpoint",
            Self::LoadAddrMisaligned     => "Load address misaligned",
            Self::LoadAccessFault        => "Load access fault",
            Self::StoreAmoMisaligned     => "Store/AMO address misaligned",
            Self::StoreAmoAccessFault    => "Store/AMO access fault",
            Self::EcallFromU             => "Environment call from U-mode",
            Self::EcallFromS             => "Environment call from S-mode",
            Self::EcallFromVS            => "Environment call from VS-mode",
            Self::EcallFromM             => "Environment call from M-mode",
            Self::InstrPageFault         => "Instruction page fault",
            Self::LoadPageFault          => "Load page fault",
            Self::StoreAmoPageFault      => "Store/AMO page fault",
            Self::InstrGuestPageFault    => "Instruction guest-page fault",
            Self::LoadGuestPageFault     => "Load guest-page fault",
            Self::VirtualInstruction     => "Virtual instruction",
            Self::StoreAmoGuestPageFault => "Store/AMO guest-page fault",
            Self::Unknown(_)             => "Unknown exception",
        }
    }

    /// Returns `true` for exceptions that involve a memory address in `mtval`/`stval`.
    #[must_use]
    pub fn has_tval_address(self) -> bool {
        matches!(
            self,
            Self::InstrAddrMisaligned
                | Self::InstrAccessFault
                | Self::LoadAddrMisaligned
                | Self::LoadAccessFault
                | Self::StoreAmoMisaligned
                | Self::StoreAmoAccessFault
                | Self::InstrPageFault
                | Self::LoadPageFault
                | Self::StoreAmoPageFault
        )
    }

    /// Returns `true` for system-call exceptions.
    #[must_use]
    pub fn is_ecall(self) -> bool {
        matches!(
            self,
            Self::EcallFromU | Self::EcallFromS | Self::EcallFromVS | Self::EcallFromM
        )
    }
}

impl fmt::Display for ExceptionCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.description())
    }
}

/// Interrupt codes (mcause/scause with bit63/31=1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum InterruptCode {
    UserSoftware,
    SupervisorSoftware,
    VsSoftware,
    MachineSoftware,
    UserTimer,
    SupervisorTimer,
    VsTimer,
    MachineTimer,
    UserExternal,
    SupervisorExternal,
    VsExternal,
    MachineExternal,
    SupervisorGuest,
    Unknown(u64),
}

impl InterruptCode {
    /// Decode from a raw interrupt code.
    #[must_use]
    pub fn from_raw(code: u64) -> Self {
        match code {
            0  => Self::UserSoftware,
            1  => Self::SupervisorSoftware,
            2  => Self::VsSoftware,
            3  => Self::MachineSoftware,
            4  => Self::UserTimer,
            5  => Self::SupervisorTimer,
            6  => Self::VsTimer,
            7  => Self::MachineTimer,
            8  => Self::UserExternal,
            9  => Self::SupervisorExternal,
            10 => Self::VsExternal,
            11 => Self::MachineExternal,
            12 => Self::SupervisorGuest,
            n  => Self::Unknown(n),
        }
    }

    /// Return the raw interrupt code value.
    #[must_use]
    pub fn code(self) -> u64 {
        match self {
            Self::UserSoftware       => 0,
            Self::SupervisorSoftware => 1,
            Self::VsSoftware         => 2,
            Self::MachineSoftware    => 3,
            Self::UserTimer          => 4,
            Self::SupervisorTimer    => 5,
            Self::VsTimer            => 6,
            Self::MachineTimer       => 7,
            Self::UserExternal       => 8,
            Self::SupervisorExternal => 9,
            Self::VsExternal         => 10,
            Self::MachineExternal    => 11,
            Self::SupervisorGuest    => 12,
            Self::Unknown(n)         => n,
        }
    }

    /// Short description.
    #[must_use]
    pub fn description(self) -> &'static str {
        match self {
            Self::UserSoftware       => "User software interrupt",
            Self::SupervisorSoftware => "Supervisor software interrupt",
            Self::VsSoftware         => "VS-level software interrupt",
            Self::MachineSoftware    => "Machine software interrupt",
            Self::UserTimer          => "User timer interrupt",
            Self::SupervisorTimer    => "Supervisor timer interrupt",
            Self::VsTimer            => "VS-level timer interrupt",
            Self::MachineTimer       => "Machine timer interrupt",
            Self::UserExternal       => "User external interrupt",
            Self::SupervisorExternal => "Supervisor external interrupt",
            Self::VsExternal         => "VS-level external interrupt",
            Self::MachineExternal    => "Machine external interrupt",
            Self::SupervisorGuest    => "Supervisor guest external interrupt",
            Self::Unknown(_)         => "Unknown interrupt",
        }
    }
}

impl fmt::Display for InterruptCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.description())
    }
}

/// A fully decoded RISC-V trap cause.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrapCause {
    Exception(ExceptionCode),
    Interrupt(InterruptCode),
}

impl TrapCause {
    /// Kind of this trap.
    #[must_use]
    pub fn kind(&self) -> TrapKind {
        match self {
            Self::Exception(_) => TrapKind::Exception,
            Self::Interrupt(_) => TrapKind::Interrupt,
        }
    }

    /// Human-readable description.
    #[must_use]
    pub fn description(&self) -> &'static str {
        match self {
            Self::Exception(e) => e.description(),
            Self::Interrupt(i) => i.description(),
        }
    }
}

impl fmt::Display for TrapCause {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {}", self.kind(), self.description())
    }
}

/// Decode mcause or scause into a `TrapCause`.
///
/// `xlen` must be 32 or 64.
#[must_use]
pub fn mcause_decode(cause: u64, xlen: u32) -> TrapCause {
    let (is_interrupt, code) = if xlen == 32 {
        ((cause >> 31) & 1 == 1, cause & 0x7FFF_FFFF)
    } else {
        ((cause >> 63) & 1 == 1, cause & 0x7FFF_FFFF_FFFF_FFFF)
    };
    if is_interrupt {
        TrapCause::Interrupt(InterruptCode::from_raw(code))
    } else {
        TrapCause::Exception(ExceptionCode::from_raw(code))
    }
}

// ── mtvec / exception vector ──────────────────────────────────────────────────

/// mtvec mode (bits [1:0]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TvecMode {
    /// Direct mode: all exceptions jump to BASE.
    Direct,
    /// Vectored mode: async interrupts jump to BASE + 4 * cause.
    Vectored,
    /// Reserved.
    Reserved(u8),
}

impl TvecMode {
    /// Decode from the raw mtvec value.
    #[must_use]
    pub fn from_mtvec(mtvec: u64) -> Self {
        match (mtvec & 0x3) as u8 {
            0 => Self::Direct,
            1 => Self::Vectored,
            n => Self::Reserved(n),
        }
    }
}

impl fmt::Display for TvecMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Direct       => f.write_str("Direct"),
            Self::Vectored     => f.write_str("Vectored"),
            Self::Reserved(n)  => write!(f, "Reserved({n})"),
        }
    }
}

/// A parsed trap-vector table entry.
#[derive(Debug, Clone)]
pub struct ExceptionVector {
    /// The interrupt code this vector entry corresponds to.
    pub interrupt_code: u64,
    /// The interrupt name.
    pub name: String,
    /// The computed handler address: `BASE + 4 * interrupt_code`.
    pub handler_addr: u64,
}

impl ExceptionVector {
    /// Create a new vector entry for `interrupt_code` given `mtvec`.
    #[must_use]
    pub fn new(mtvec: u64, interrupt_code: u64) -> Self {
        let base = mtvec & !0x3;
        let handler_addr = base + 4 * interrupt_code;
        let name = InterruptCode::from_raw(interrupt_code).description().to_string();
        Self {
            interrupt_code,
            name,
            handler_addr,
        }
    }
}

impl fmt::Display for ExceptionVector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "IRQ {:2}: {:40}  handler=0x{:016X}",
            self.interrupt_code, self.name, self.handler_addr
        )
    }
}

// ── Exception handler analyser ────────────────────────────────────────────────

/// State that describes one privilege-level trap configuration.
#[derive(Debug, Clone)]
pub struct TrapConfig {
    /// mtvec / stvec value.
    pub tvec: u64,
    /// Decoded mode.
    pub mode: TvecMode,
    /// Base address (aligned).
    pub base: u64,
    /// mscratch / sscratch value (if known).
    pub scratch: Option<u64>,
    /// mepc / sepc value (last known).
    pub epc: Option<u64>,
}

impl TrapConfig {
    /// Build a `TrapConfig` from a raw tvec value.
    #[must_use]
    pub fn from_tvec(tvec: u64) -> Self {
        let mode = TvecMode::from_mtvec(tvec);
        let base = tvec & !0x3u64;
        Self {
            tvec,
            mode,
            base,
            scratch: None,
            epc: None,
        }
    }

    /// Compute the handler address for a given cause value.
    ///
    /// In Vectored mode, interrupts are dispatched to `BASE + 4*cause_code`.
    /// In Direct mode, all traps go to `BASE`.
    #[must_use]
    pub fn handler_for(&self, cause: u64, xlen: u32) -> u64 {
        let trap = mcause_decode(cause, xlen);
        match (self.mode, &trap) {
            (TvecMode::Vectored, TrapCause::Interrupt(c)) => {
                let code = c.code();
                self.base + 4 * code
            }
            _ => self.base,
        }
    }

    /// List all vectored interrupt handler addresses (codes 0–12).
    #[must_use]
    pub fn vectored_table(&self) -> Vec<ExceptionVector> {
        (0u64..=12)
            .map(|code| ExceptionVector::new(self.tvec, code))
            .collect()
    }
}

/// Maximum number of trap records kept in the history buffer.
///
/// Prevents unbounded memory growth when `record_trap` is called with
/// attacker-controlled frequency (dos-memory-exhaustion).
pub const MAX_TRAP_HISTORY: usize = 65_536;

/// Analyser for a RISC-V machine's exception/interrupt handling setup.
#[derive(Debug, Clone)]
pub struct RiscvExceptionHandler {
    /// XLEN (32 or 64).
    pub xlen: u32,
    /// Machine-mode trap config (mtvec, mscratch, …).
    pub machine: TrapConfig,
    /// Supervisor-mode trap config (stvec, sscratch, …).
    pub supervisor: Option<TrapConfig>,
    /// Historical trap records for analysis.
    history: Vec<TrapRecord>,
}

/// A recorded trap event for post-mortem analysis.
#[derive(Debug, Clone)]
pub struct TrapRecord {
    /// Raw mcause / scause value.
    pub raw_cause: u64,
    /// Decoded cause.
    pub cause: TrapCause,
    /// EPC at time of trap.
    pub epc: u64,
    /// tval at time of trap.
    pub tval: u64,
    /// Privilege level where the trap was taken (0=U, 1=S, 3=M).
    pub taken_at_priv: u8,
}

impl RiscvExceptionHandler {
    /// Create a new handler analyser.
    ///
    /// - `xlen` — 32 or 64
    /// - `mtvec` — machine trap vector CSR value
    #[must_use]
    pub fn new(xlen: u32, mtvec: u64) -> Self {
        Self {
            xlen,
            machine: TrapConfig::from_tvec(mtvec),
            supervisor: None,
            history: Vec::new(),
        }
    }

    /// Set the supervisor-mode trap vector.
    pub fn set_stvec(&mut self, stvec: u64) {
        self.supervisor = Some(TrapConfig::from_tvec(stvec));
    }

    /// Set the machine-mode scratch register.
    pub fn set_mscratch(&mut self, val: u64) {
        self.machine.scratch = Some(val);
    }

    /// Set the supervisor-mode scratch register.
    ///
    /// Returns `false` (state-machine-skipped guard) if [`set_stvec`] has not
    /// been called yet — the value is not silently discarded; the caller can
    /// detect the wrong-state condition.
    ///
    /// [`set_stvec`]: Self::set_stvec
    pub fn set_sscratch(&mut self, val: u64) -> bool {
        if let Some(ref mut s) = self.supervisor {
            s.scratch = Some(val);
            true
        } else {
            false
        }
    }

    /// Record a trap for history tracking.
    ///
    /// Silently drops the record once [`MAX_TRAP_HISTORY`] entries have
    /// accumulated, preventing dos-memory-exhaustion when the caller feeds
    /// untrusted input.
    pub fn record_trap(&mut self, raw_cause: u64, epc: u64, tval: u64, priv_: u8) {
        if self.history.len() >= MAX_TRAP_HISTORY {
            return;
        }
        let cause = mcause_decode(raw_cause, self.xlen);
        self.history.push(TrapRecord {
            raw_cause,
            cause,
            epc,
            tval,
            taken_at_priv: priv_,
        });
    }

    /// Compute the machine-mode handler for a given cause value.
    #[must_use]
    pub fn machine_handler(&self, cause: u64) -> u64 {
        self.machine.handler_for(cause, self.xlen)
    }

    /// Compute the supervisor-mode handler for a given cause, if stvec is set.
    #[must_use]
    pub fn supervisor_handler(&self, cause: u64) -> Option<u64> {
        self.supervisor
            .as_ref()
            .map(|s| s.handler_for(cause, self.xlen))
    }

    /// Return the vectored interrupt table for M-mode.
    #[must_use]
    pub fn machine_vector_table(&self) -> Vec<ExceptionVector> {
        self.machine.vectored_table()
    }

    /// Return the history of recorded traps.
    #[must_use]
    pub fn history(&self) -> &[TrapRecord] {
        &self.history
    }

    /// Count how many times each exception code appeared in history.
    #[must_use]
    pub fn exception_histogram(&self) -> HashMap<u64, usize> {
        let mut map: HashMap<u64, usize> = HashMap::new();
        for rec in &self.history {
            *map.entry(rec.raw_cause).or_insert(0) += 1;
        }
        map
    }

    /// Summarise the trap configuration as a human-readable string.
    #[must_use]
    pub fn summary(&self) -> String {
        let mut s = format!(
            "RISC-V{} Exception Handler Summary\n",
            self.xlen
        );
        s.push_str(&format!(
            "  mtvec = 0x{:016X}  mode={}\n",
            self.machine.tvec, self.machine.mode
        ));
        s.push_str(&format!("  M-mode base = 0x{:016X}\n", self.machine.base));
        if let Some(ref sup) = self.supervisor {
            s.push_str(&format!(
                "  stvec = 0x{:016X}  mode={}\n",
                sup.tvec, sup.mode
            ));
        }
        s.push_str(&format!("  Trap history: {} records\n", self.history.len()));
        s
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mcause_decode_exception_ecall_m() {
        let cause = mcause_decode(11, 64);
        assert_eq!(cause.kind(), TrapKind::Exception);
        assert_eq!(
            cause,
            TrapCause::Exception(ExceptionCode::EcallFromM)
        );
    }

    #[test]
    fn test_mcause_decode_interrupt_machine_timer() {
        let cause = mcause_decode(0x8000_0000_0000_0007, 64);
        assert_eq!(cause.kind(), TrapKind::Interrupt);
        assert_eq!(
            cause,
            TrapCause::Interrupt(InterruptCode::MachineTimer)
        );
    }

    #[test]
    fn test_mcause_decode_rv32_interrupt() {
        let cause = mcause_decode(0x8000_0007, 32);
        assert_eq!(cause, TrapCause::Interrupt(InterruptCode::MachineTimer));
    }

    #[test]
    fn test_mcause_decode_illegal_insn() {
        let cause = mcause_decode(2, 64);
        assert_eq!(
            cause,
            TrapCause::Exception(ExceptionCode::IllegalInstruction)
        );
    }

    #[test]
    fn test_mcause_decode_breakpoint() {
        let cause = mcause_decode(3, 64);
        assert_eq!(cause, TrapCause::Exception(ExceptionCode::Breakpoint));
    }

    #[test]
    fn test_exception_code_has_tval() {
        assert!(ExceptionCode::LoadAddrMisaligned.has_tval_address());
        assert!(ExceptionCode::LoadPageFault.has_tval_address());
        assert!(!ExceptionCode::EcallFromM.has_tval_address());
        assert!(!ExceptionCode::Breakpoint.has_tval_address());
    }

    #[test]
    fn test_exception_code_is_ecall() {
        assert!(ExceptionCode::EcallFromU.is_ecall());
        assert!(ExceptionCode::EcallFromM.is_ecall());
        assert!(!ExceptionCode::Breakpoint.is_ecall());
    }

    #[test]
    fn test_trap_cause_display() {
        let c = TrapCause::Exception(ExceptionCode::IllegalInstruction);
        let s = format!("{c}");
        assert!(s.contains("Illegal"));
        assert!(s.contains("Exception"));
    }

    #[test]
    fn test_tvec_mode_direct() {
        let mode = TvecMode::from_mtvec(0x8000_0000);
        assert_eq!(mode, TvecMode::Direct);
    }

    #[test]
    fn test_tvec_mode_vectored() {
        let mode = TvecMode::from_mtvec(0x8000_0001);
        assert_eq!(mode, TvecMode::Vectored);
    }

    #[test]
    fn test_trap_config_direct_handler() {
        let cfg = TrapConfig::from_tvec(0x8000_0000);
        // In Direct mode every cause goes to base
        let h = cfg.handler_for(0x8000_0000_0000_0007, 64); // machine timer interrupt
        assert_eq!(h, 0x8000_0000);
    }

    #[test]
    fn test_trap_config_vectored_handler() {
        let cfg = TrapConfig::from_tvec(0x8000_0001); // vectored at 0x8000_0000
        // Machine timer (code=7): handler = 0x8000_0000 + 4*7 = 0x8000_001C
        let cause = 0x8000_0000_0000_0007u64;
        let h = cfg.handler_for(cause, 64);
        assert_eq!(h, 0x8000_0000 + 4 * 7);
    }

    #[test]
    fn test_trap_config_vectored_exception_goes_to_base() {
        // Exceptions always go to base in vectored mode
        let cfg = TrapConfig::from_tvec(0x8000_0001);
        let h = cfg.handler_for(11, 64); // ecall from M
        assert_eq!(h, 0x8000_0000);
    }

    #[test]
    fn test_vector_table_len() {
        let cfg = TrapConfig::from_tvec(0x8000_0001);
        let table = cfg.vectored_table();
        assert_eq!(table.len(), 13); // codes 0..=12
    }

    #[test]
    fn test_exception_handler_summary() {
        let h = RiscvExceptionHandler::new(64, 0x8000_0000);
        let s = h.summary();
        assert!(s.contains("mtvec"));
        assert!(s.contains("RISC-V64"));
    }

    #[test]
    fn test_exception_handler_record() {
        let mut h = RiscvExceptionHandler::new(64, 0x8000_0000);
        h.record_trap(11, 0x1000, 0, 3); // ecall from M at pc=0x1000
        assert_eq!(h.history().len(), 1);
        let rec = &h.history()[0];
        assert_eq!(rec.epc, 0x1000);
        assert_eq!(rec.cause, TrapCause::Exception(ExceptionCode::EcallFromM));
    }

    #[test]
    fn test_exception_handler_histogram() {
        let mut h = RiscvExceptionHandler::new(64, 0x8000_0000);
        h.record_trap(11, 0x1000, 0, 3);
        h.record_trap(11, 0x1004, 0, 3);
        h.record_trap(3,  0x2000, 0, 3);
        let hist = h.exception_histogram();
        assert_eq!(hist[&11], 2);
        assert_eq!(hist[&3], 1);
    }

    #[test]
    fn test_supervisor_handler() {
        let mut h = RiscvExceptionHandler::new(64, 0x8000_0000);
        h.set_stvec(0x9000_0000);
        let addr = h.supervisor_handler(9).unwrap(); // ecall from S
        assert_eq!(addr, 0x9000_0000); // direct mode
    }

    #[test]
    fn test_machine_vectored_handler() {
        let h = RiscvExceptionHandler::new(64, 0x8000_0001);
        // Machine external interrupt = code 11
        let cause = (1u64 << 63) | 11;
        let addr = h.machine_handler(cause);
        assert_eq!(addr, 0x8000_0000 + 4 * 11);
    }

    #[test]
    fn test_interrupt_code_display() {
        let c = InterruptCode::MachineSoftware;
        assert!(c.to_string().contains("Machine software"));
    }

    #[test]
    fn test_exception_code_display() {
        let c = ExceptionCode::InstrPageFault;
        assert!(c.to_string().contains("page fault"));
    }

    #[test]
    fn test_exception_vector_display() {
        let v = ExceptionVector::new(0x8000_0001, 7);
        let s = format!("{v}");
        assert!(s.contains("Machine timer"));
    }

    #[test]
    fn test_unknown_exception_code() {
        let c = ExceptionCode::from_raw(99);
        assert_eq!(c.description(), "Unknown exception");
        assert_eq!(c, ExceptionCode::Unknown(99));
    }

    #[test]
    fn test_unknown_interrupt_code() {
        let c = InterruptCode::from_raw(99);
        assert_eq!(c.description(), "Unknown interrupt");
    }

    #[test]
    fn test_trap_kind_display() {
        assert_eq!(TrapKind::Exception.to_string(), "Exception");
        assert_eq!(TrapKind::Interrupt.to_string(), "Interrupt");
    }

    #[test]
    fn test_tvec_mode_display() {
        assert_eq!(TvecMode::Direct.to_string(), "Direct");
        assert_eq!(TvecMode::Vectored.to_string(), "Vectored");
    }

    #[test]
    fn test_mscratch_tracking() {
        let mut h = RiscvExceptionHandler::new(64, 0x8000_0000);
        h.set_mscratch(0xDEAD_BEEF);
        assert_eq!(h.machine.scratch, Some(0xDEAD_BEEF));
    }

    #[test]
    fn test_ecall_all_modes() {
        for (raw, expected) in [
            (8u64,  ExceptionCode::EcallFromU),
            (9u64,  ExceptionCode::EcallFromS),
            (10u64, ExceptionCode::EcallFromVS),
            (11u64, ExceptionCode::EcallFromM),
        ] {
            let cause = mcause_decode(raw, 64);
            assert_eq!(cause, TrapCause::Exception(expected));
        }
    }

    #[test]
    fn test_store_amo_page_fault() {
        let cause = mcause_decode(15, 64);
        assert_eq!(cause, TrapCause::Exception(ExceptionCode::StoreAmoPageFault));
        if let TrapCause::Exception(e) = cause {
            assert!(e.has_tval_address());
        }
    }
}
