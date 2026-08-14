//! x86 string instruction lifting.
//!
//! Models REP / REPNE / REPE prefixed versions of:
//!   MOVS  CMPS  SCAS  LODS  STOS  INS  OUTS
//!
//! # Semantics
//! A REP-prefixed string op is modelled as:
//! ```text
//! while ECX/RCX != 0 {
//!     <operation>
//!     ECX -= 1
//!     RSI/RDI += ±operand_size   (depending on DF)
//! }
//! ```
//!
//! The looping structure is represented as a pair of IL intrinsics
//! (`rep_loop_enter` / `rep_loop_exit`) surrounding the body effects.
//! This keeps the IR flat while preserving enough structure for a
//! subsequent analysis pass to recognise the rep-loop pattern.
//!
//! # Dispatch status (NOT wired into `src/lift.rs`)
//!
//! This module is **not** part of the active lifting path. `src/lift.rs`
//! dispatches every mnemonic directly via its own native match arms (added
//! across several hardening passes), and does not call into this module.
//! It is intentionally retained -- not dead code pending removal -- per
//! explicit user instruction, as a possible future cross-validation /
//! second-opinion decode path independent of `lift.rs`.

use rustre_il_lift::{Effect, IrExpr};

// ─────────────────────────────────────────────────────────────────────────────
// DirectionFlag
// ─────────────────────────────────────────────────────────────────────────────

/// Models the x86 direction flag (DF).
///
/// When `DF = 0` (CLD), RSI/RDI increment; when `DF = 1` (STD) they decrement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum DirectionFlag {
    /// DF = 0: increment pointers after each iteration (default).
    #[default]
    Up,
    /// DF = 1: decrement pointers after each iteration.
    Down,
    /// DF is unknown at lift time — emit a runtime branch.
    Unknown,
}

impl DirectionFlag {
    /// An `IrExpr` representing the direction flag register.
    #[must_use]
    pub fn expr() -> IrExpr {
        IrExpr::Reg("df".to_string())
    }

    /// Signed displacement for a pointer update (+size or -size).
    ///
    /// Returns `None` when the direction is unknown (caller must emit a
    /// runtime conditional).
    #[must_use]
    pub fn displacement(self, size: u8) -> Option<i64> {
        match self {
            Self::Up => Some(i64::from(size)),
            Self::Down => Some(-i64::from(size)),
            Self::Unknown => None,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// RepeatPrefix
// ─────────────────────────────────────────────────────────────────────────────

/// The REP / REPNE / REPE prefix on a string instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum RepeatPrefix {
    /// No repeat prefix.
    #[default]
    None,
    /// REP / REPE — repeat while ZF = 1 (used with CMPS / SCAS).
    Rep,
    /// REPNE — repeat while ZF = 0 (used with CMPS / SCAS).
    Repne,
}

impl RepeatPrefix {
    /// Returns `true` if any repeat prefix is present.
    #[must_use]
    pub fn is_present(self) -> bool {
        self != Self::None
    }

    /// The counter register name for the configured address size.
    #[must_use]
    pub fn counter_reg(addr_bits: u8) -> &'static str {
        match addr_bits {
            64 => "rcx",
            32 => "ecx",
            _ => "cx",
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// RepeatController
// ─────────────────────────────────────────────────────────────────────────────

/// Wraps a body of `Effect`s with the REP loop bookends.
///
/// Emits:
/// 1. `rep_loop_enter(counter_reg)` — marks loop entry and records ECX/RCX
/// 2. `<body effects>`
/// 3. Counter decrement: `counter_reg` -= 1
/// 4. `rep_loop_exit(condition)` — models the loop back-edge / exit condition
pub struct RepeatController {
    /// Address size in bits (16, 32, or 64).
    pub addr_bits: u8,
    /// Repeat prefix.
    pub prefix: RepeatPrefix,
}

impl RepeatController {
    /// Create a new controller.
    #[must_use]
    pub fn new(addr_bits: u8, prefix: RepeatPrefix) -> Self {
        Self { addr_bits, prefix }
    }

    /// Wrap `body` with loop enter/exit effects and counter management.
    ///
    /// If `prefix` is `None`, returns `body` unchanged.
    ///
    /// This assumes a ZF-dependent (string-compare) body, i.e. CMPS/SCAS.
    /// For count-only ops (MOVS/STOS/LODS/INS/OUTS) use [`Self::wrap_op`]
    /// with `zf_dependent = false`.
    #[must_use]
    pub fn wrap(&self, body: Vec<Effect>) -> Vec<Effect> {
        self.wrap_op(body, true)
    }

    /// Wrap `body` with loop enter/exit effects and counter management.
    ///
    /// `zf_dependent` must be `true` only for string-compare forms
    /// (CMPS/SCAS), where REPE/REPNE additionally terminate on ZF. For
    /// MOVS/STOS/LODS/INS/OUTS the REP prefix is count-only and the exit
    /// condition is solely `counter == 0`.
    #[must_use]
    pub fn wrap_op(&self, body: Vec<Effect>, zf_dependent: bool) -> Vec<Effect> {
        if !self.prefix.is_present() {
            return body;
        }

        let counter = RepeatPrefix::counter_reg(self.addr_bits);
        let counter_expr = IrExpr::Reg(counter.to_string());

        let mut out = Vec::new();

        // Loop entry marker
        out.push(Effect::Intrinsic {
            name: "rep_loop_enter".to_string(),
            args: vec![counter_expr.clone()],
        });

        // Body
        out.extend(body);

        // Decrement counter
        out.push(Effect::RegWrite {
            reg: counter.to_string(),
            value: IrExpr::Sub(Box::new(counter_expr.clone()), Box::new(IrExpr::Const(1))),
        });

        // Loop exit condition.
        //
        // x86 semantics: the loop exits when the counter reaches zero OR
        // (for the string-compare forms only) the ZF termination condition
        // holds. Either condition alone suffices — hence `Or`, never `And`.
        // For non-compare bodies (MOVS/STOS/LODS/INS/OUTS) REP is count-only
        // and ZF is ignored entirely.
        let counter_zero = IrExpr::CmpEqZero(Box::new(counter_expr.clone()));
        let cond = match (self.prefix, zf_dependent) {
            (RepeatPrefix::Rep, true) => IrExpr::Or(
                Box::new(counter_zero),
                Box::new(IrExpr::Not(Box::new(IrExpr::Reg("zf".to_string())))),
            ),
            (RepeatPrefix::Repne, true) => IrExpr::Or(
                Box::new(counter_zero),
                Box::new(IrExpr::Reg("zf".to_string())),
            ),
            (RepeatPrefix::Rep | RepeatPrefix::Repne, false) => counter_zero,
            (RepeatPrefix::None, _) => IrExpr::Const(1),
        };
        out.push(Effect::Intrinsic {
            name: "rep_loop_exit".to_string(),
            args: vec![cond],
        });

        out
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// StringOpContext
// ─────────────────────────────────────────────────────────────────────────────

/// Shared context for a string-instruction lifting session.
#[derive(Debug, Clone)]
pub struct StringOpContext {
    /// Bit-width of the address space (16 / 32 / 64).
    pub addr_bits: u8,
    /// Operand size in bytes (1 / 2 / 4 / 8).
    pub op_size: u8,
    /// Direction flag model.
    pub df: DirectionFlag,
    /// REP / REPNE prefix in effect.
    pub prefix: RepeatPrefix,
}

impl StringOpContext {
    /// Create a context for the most common 64-bit case.
    #[must_use]
    pub fn new_64() -> Self {
        Self {
            addr_bits: 64,
            op_size: 8,
            df: DirectionFlag::Up,
            prefix: RepeatPrefix::None,
        }
    }

    /// Create a 32-bit context.
    #[must_use]
    pub fn new_32() -> Self {
        Self {
            addr_bits: 32,
            op_size: 4,
            df: DirectionFlag::Up,
            prefix: RepeatPrefix::None,
        }
    }

    /// Apply a REP prefix.
    #[must_use]
    pub fn with_rep(mut self) -> Self {
        self.prefix = RepeatPrefix::Rep;
        self
    }

    /// Apply a REPNE prefix.
    #[must_use]
    pub fn with_repne(mut self) -> Self {
        self.prefix = RepeatPrefix::Repne;
        self
    }

    /// Set the direction flag to down (STD).
    #[must_use]
    pub fn std(mut self) -> Self {
        self.df = DirectionFlag::Down;
        self
    }

    /// Source index register name.
    #[must_use]
    pub fn rsi(&self) -> &'static str {
        match self.addr_bits {
            64 => "rsi",
            32 => "esi",
            _ => "si",
        }
    }

    /// Destination index register name.
    #[must_use]
    pub fn rdi(&self) -> &'static str {
        match self.addr_bits {
            64 => "rdi",
            32 => "edi",
            _ => "di",
        }
    }

    /// The accumulator register name (for LODS / STOS / SCAS).
    #[must_use]
    pub fn rax(&self) -> &'static str {
        match (self.addr_bits, self.op_size) {
            (_, 1) => "al",
            (_, 2) => "ax",
            (_, 4) => "eax",
            _ => "rax",
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// StringOpLifter
// ─────────────────────────────────────────────────────────────────────────────

/// Lifts x86 string instructions to IL effects.
pub struct StringOpLifter {
    ctx: StringOpContext,
}

impl StringOpLifter {
    /// Create a lifter with the given context.
    #[must_use]
    pub fn new(ctx: StringOpContext) -> Self {
        Self { ctx }
    }

    /// Lift a string instruction by mnemonic.
    ///
    /// The mnemonic should be the bare instruction without the operand-size
    /// suffix (e.g. `"movs"` not `"movsb"`).  The context's `op_size` field
    /// determines element size.
    #[must_use]
    pub fn lift(&self, mnemonic: &str) -> Vec<Effect> {
        let body = self.lift_body(mnemonic);
        // Only the string-compare forms (CMPS/SCAS) have ZF-dependent
        // REPE/REPNE termination; for all other string ops REP is count-only.
        let zf_dependent = matches!(
            mnemonic
                .to_ascii_lowercase()
                .trim_end_matches(|c| "bwdq".contains(c)),
            "cmps" | "scas"
        );
        let ctrl = RepeatController::new(self.ctx.addr_bits, self.ctx.prefix);
        ctrl.wrap_op(body, zf_dependent)
    }

    // ── Private body emitters ─────────────────────────────────────────────────

    fn lift_body(&self, mnemonic: &str) -> Vec<Effect> {
        match mnemonic
            .to_ascii_lowercase()
            .trim_end_matches(|c| "bwdq".contains(c))
        {
            "movs" => self.emit_movs(),
            "cmps" => self.emit_cmps(),
            "scas" => self.emit_scas(),
            "lods" => self.emit_lods(),
            "stos" => self.emit_stos(),
            "ins" => self.emit_ins(),
            "outs" => self.emit_outs(),
            other => vec![Effect::Intrinsic {
                name: format!("__string_{other}"),
                args: vec![],
            }],
        }
    }

    /// MOVS: [RDI] = [RSI]; advance RSI and RDI
    fn emit_movs(&self) -> Vec<Effect> {
        let rsi = IrExpr::Reg(self.ctx.rsi().to_string());
        let rdi = IrExpr::Reg(self.ctx.rdi().to_string());
        let sz = self.ctx.op_size;

        let mut effs = vec![
            // tmp = [RSI]
            Effect::MemRead {
                addr: rsi.clone(),
                dest: "__movs_tmp".to_string(),
                size: sz,
            },
            // [RDI] = tmp
            Effect::MemWrite {
                addr: rdi.clone(),
                value: IrExpr::Reg("__movs_tmp".to_string()),
                size: sz,
            },
        ];

        effs.extend(self.advance_ptr(self.ctx.rsi()));
        effs.extend(self.advance_ptr(self.ctx.rdi()));
        effs
    }

    /// CMPS: compare [RSI] with [RDI], set flags, advance both pointers
    fn emit_cmps(&self) -> Vec<Effect> {
        let rsi = IrExpr::Reg(self.ctx.rsi().to_string());
        let rdi = IrExpr::Reg(self.ctx.rdi().to_string());
        let sz = self.ctx.op_size;

        let mut effs = vec![
            Effect::MemRead {
                addr: rsi.clone(),
                dest: "__cmps_a".to_string(),
                size: sz,
            },
            Effect::MemRead {
                addr: rdi.clone(),
                dest: "__cmps_b".to_string(),
                size: sz,
            },
            // flags = a - b
            Effect::Intrinsic {
                name: "set_flags_sub".to_string(),
                args: vec![
                    IrExpr::Reg("__cmps_a".to_string()),
                    IrExpr::Reg("__cmps_b".to_string()),
                ],
            },
            // ZF = (a == b)
            Effect::RegWrite {
                reg: "zf".to_string(),
                value: IrExpr::CmpEqZero(Box::new(IrExpr::Sub(
                    Box::new(IrExpr::Reg("__cmps_a".to_string())),
                    Box::new(IrExpr::Reg("__cmps_b".to_string())),
                ))),
            },
        ];

        effs.extend(self.advance_ptr(self.ctx.rsi()));
        effs.extend(self.advance_ptr(self.ctx.rdi()));
        effs
    }

    /// SCAS: compare AL/AX/EAX/RAX with [RDI], set flags, advance RDI
    fn emit_scas(&self) -> Vec<Effect> {
        let rdi = IrExpr::Reg(self.ctx.rdi().to_string());
        let rax = IrExpr::Reg(self.ctx.rax().to_string());
        let sz = self.ctx.op_size;

        let mut effs = vec![
            Effect::MemRead {
                addr: rdi.clone(),
                dest: "__scas_mem".to_string(),
                size: sz,
            },
            Effect::Intrinsic {
                name: "set_flags_sub".to_string(),
                args: vec![rax.clone(), IrExpr::Reg("__scas_mem".to_string())],
            },
            Effect::RegWrite {
                reg: "zf".to_string(),
                value: IrExpr::CmpEqZero(Box::new(IrExpr::Sub(
                    Box::new(rax),
                    Box::new(IrExpr::Reg("__scas_mem".to_string())),
                ))),
            },
        ];

        effs.extend(self.advance_ptr(self.ctx.rdi()));
        effs
    }

    /// LODS: AL/AX/EAX/RAX = [RSI]; advance RSI
    fn emit_lods(&self) -> Vec<Effect> {
        let rsi = IrExpr::Reg(self.ctx.rsi().to_string());
        let sz = self.ctx.op_size;

        let mut effs = vec![Effect::MemRead {
            addr: rsi,
            dest: self.ctx.rax().to_string(),
            size: sz,
        }];
        effs.extend(self.advance_ptr(self.ctx.rsi()));
        effs
    }

    /// STOS: [RDI] = AL/AX/EAX/RAX; advance RDI
    fn emit_stos(&self) -> Vec<Effect> {
        let rdi = IrExpr::Reg(self.ctx.rdi().to_string());
        let rax = IrExpr::Reg(self.ctx.rax().to_string());
        let sz = self.ctx.op_size;

        let mut effs = vec![Effect::MemWrite {
            addr: rdi,
            value: rax,
            size: sz,
        }];
        effs.extend(self.advance_ptr(self.ctx.rdi()));
        effs
    }

    /// INS: [RDI] = IO[DX]; advance RDI
    fn emit_ins(&self) -> Vec<Effect> {
        let rdi = IrExpr::Reg(self.ctx.rdi().to_string());
        let sz = self.ctx.op_size;

        let mut effs = vec![
            Effect::Intrinsic {
                name: "io_read".to_string(),
                args: vec![IrExpr::Reg("dx".to_string())],
            },
            Effect::MemWrite {
                addr: rdi,
                value: IrExpr::Reg("__io_data".to_string()),
                size: sz,
            },
        ];
        effs.extend(self.advance_ptr(self.ctx.rdi()));
        effs
    }

    /// OUTS: IO[DX] = [RSI]; advance RSI
    fn emit_outs(&self) -> Vec<Effect> {
        let rsi = IrExpr::Reg(self.ctx.rsi().to_string());
        let sz = self.ctx.op_size;

        let mut effs = vec![
            Effect::MemRead {
                addr: rsi,
                dest: "__outs_data".to_string(),
                size: sz,
            },
            Effect::Intrinsic {
                name: "io_write".to_string(),
                args: vec![
                    IrExpr::Reg("dx".to_string()),
                    IrExpr::Reg("__outs_data".to_string()),
                ],
            },
        ];
        effs.extend(self.advance_ptr(self.ctx.rsi()));
        effs
    }

    // ── Pointer advancement ───────────────────────────────────────────────────

    /// Emit effects to advance a pointer register by `±op_size` depending on DF.
    fn advance_ptr(&self, reg: &'static str) -> Vec<Effect> {
        let ptr = IrExpr::Reg(reg.to_string());
        let sz = u64::from(self.ctx.op_size);

        match self.ctx.df {
            DirectionFlag::Up => vec![Effect::RegWrite {
                reg: reg.to_string(),
                value: IrExpr::Add(Box::new(ptr), Box::new(IrExpr::Const(sz))),
            }],
            DirectionFlag::Down => vec![Effect::RegWrite {
                reg: reg.to_string(),
                value: IrExpr::Sub(Box::new(ptr), Box::new(IrExpr::Const(sz))),
            }],
            DirectionFlag::Unknown => vec![Effect::Intrinsic {
                name: "advance_ptr_df".to_string(),
                args: vec![ptr, IrExpr::Const(sz)],
            }],
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx64() -> StringOpContext {
        StringOpContext::new_64()
    }
    fn ctx32() -> StringOpContext {
        StringOpContext::new_32()
    }

    // DirectionFlag
    #[test]
    fn df_up_displacement() {
        assert_eq!(DirectionFlag::Up.displacement(8), Some(8));
    }
    #[test]
    fn df_down_displacement() {
        assert_eq!(DirectionFlag::Down.displacement(4), Some(-4));
    }
    #[test]
    fn df_unknown_displacement() {
        assert_eq!(DirectionFlag::Unknown.displacement(1), None);
    }

    // RepeatPrefix
    #[test]
    fn rep_prefix_is_present() {
        assert!(RepeatPrefix::Rep.is_present());
        assert!(RepeatPrefix::Repne.is_present());
        assert!(!RepeatPrefix::None.is_present());
    }

    #[test]
    fn rep_counter_reg_names() {
        assert_eq!(RepeatPrefix::counter_reg(64), "rcx");
        assert_eq!(RepeatPrefix::counter_reg(32), "ecx");
        assert_eq!(RepeatPrefix::counter_reg(16), "cx");
    }

    // StringOpContext
    #[test]
    fn ctx64_registers() {
        let ctx = ctx64();
        assert_eq!(ctx.rsi(), "rsi");
        assert_eq!(ctx.rdi(), "rdi");
        assert_eq!(ctx.rax(), "rax");
    }

    #[test]
    fn ctx32_registers() {
        let ctx = ctx32();
        assert_eq!(ctx.rsi(), "esi");
        assert_eq!(ctx.rdi(), "edi");
    }

    #[test]
    fn ctx_with_rep() {
        let ctx = ctx64().with_rep();
        assert_eq!(ctx.prefix, RepeatPrefix::Rep);
    }

    #[test]
    fn ctx_with_repne() {
        let ctx = ctx64().with_repne();
        assert_eq!(ctx.prefix, RepeatPrefix::Repne);
    }

    // RepeatController
    #[test]
    fn rep_controller_wraps_with_enter_exit() {
        let ctrl = RepeatController::new(64, RepeatPrefix::Rep);
        let body = vec![Effect::Intrinsic {
            name: "nop".to_string(),
            args: vec![],
        }];
        let out = ctrl.wrap(body);
        assert!(
            out.iter()
                .any(|e| matches!(e, Effect::Intrinsic { name, .. } if name == "rep_loop_enter"))
        );
        assert!(
            out.iter()
                .any(|e| matches!(e, Effect::Intrinsic { name, .. } if name == "rep_loop_exit"))
        );
    }

    #[test]
    fn rep_controller_none_no_wrap() {
        let ctrl = RepeatController::new(64, RepeatPrefix::None);
        let body = vec![Effect::Intrinsic {
            name: "nop".to_string(),
            args: vec![],
        }];
        let out = ctrl.wrap(body.clone());
        assert_eq!(out.len(), body.len());
    }

    #[test]
    fn rep_controller_decrements_counter() {
        let ctrl = RepeatController::new(64, RepeatPrefix::Rep);
        let out = ctrl.wrap(vec![]);
        assert!(
            out.iter()
                .any(|e| matches!(e, Effect::RegWrite { reg, .. } if reg == "rcx"))
        );
    }

    fn exit_cond(effs: &[Effect]) -> &IrExpr {
        effs.iter()
            .find_map(|e| match e {
                Effect::Intrinsic { name, args } if name == "rep_loop_exit" => args.first(),
                _ => None,
            })
            .expect("rep_loop_exit present")
    }

    /// Regression: REP/REPE exit is `rcx==0 OR !zf` — either condition alone
    /// terminates the loop. The old `And` form could never terminate on
    /// RCX==0 alone.
    #[test]
    fn repe_cmps_exit_is_or_of_counter_and_not_zf() {
        let lft = StringOpLifter::new(ctx64().with_rep());
        let effs = lft.lift("cmps");
        match exit_cond(&effs) {
            IrExpr::Or(l, r) => {
                assert!(matches!(**l, IrExpr::CmpEqZero(_)));
                assert!(matches!(**r, IrExpr::Not(_)));
            }
            other => panic!("expected Or(rcx==0, !zf), got {other:?}"),
        }
    }

    /// Regression: REP on MOVS is count-only — architecturally F3 on
    /// MOVS/STOS/LODS ignores ZF entirely, so the exit condition must be
    /// exactly `rcx == 0` with no ZF term.
    #[test]
    fn rep_movs_exit_is_counter_only() {
        let lft = StringOpLifter::new(ctx64().with_rep());
        let effs = lft.lift("movs");
        match exit_cond(&effs) {
            IrExpr::CmpEqZero(inner) => {
                assert!(matches!(&**inner, IrExpr::Reg(r) if r == "rcx"));
            }
            other => panic!("expected bare rcx==0, got {other:?}"),
        }
    }

    /// Regression: REPNE SCAS exit is `rcx==0 OR zf`.
    #[test]
    fn repne_scas_exit_is_or_of_counter_and_zf() {
        let lft = StringOpLifter::new(ctx64().with_repne());
        let effs = lft.lift("scas");
        match exit_cond(&effs) {
            IrExpr::Or(l, r) => {
                assert!(matches!(**l, IrExpr::CmpEqZero(_)));
                assert!(matches!(&**r, IrExpr::Reg(z) if z == "zf"));
            }
            other => panic!("expected Or(rcx==0, zf), got {other:?}"),
        }
    }

    /// Regression: REP STOS is count-only too.
    #[test]
    fn rep_stos_exit_is_counter_only() {
        let lft = StringOpLifter::new(ctx64().with_rep());
        let effs = lft.lift("stos");
        assert!(matches!(exit_cond(&effs), IrExpr::CmpEqZero(_)));
    }

    // MOVS
    #[test]
    fn movs_reads_rsi_writes_rdi() {
        let lft = StringOpLifter::new(ctx64());
        let effs = lft.lift("movs");
        assert!(effs.iter().any(|e| matches!(e, Effect::MemRead { .. })));
        assert!(effs.iter().any(|e| matches!(e, Effect::MemWrite { .. })));
    }

    #[test]
    fn movs_advances_both_pointers() {
        let lft = StringOpLifter::new(ctx64());
        let effs = lft.lift("movs");
        let ptr_writes: Vec<_> = effs
            .iter()
            .filter(|e| matches!(e, Effect::RegWrite { reg, .. } if reg == "rsi" || reg == "rdi"))
            .collect();
        assert_eq!(ptr_writes.len(), 2);
    }

    // REP MOVS
    #[test]
    fn rep_movs_has_loop_markers() {
        let lft = StringOpLifter::new(ctx64().with_rep());
        let effs = lft.lift("movs");
        assert!(
            effs.iter()
                .any(|e| matches!(e, Effect::Intrinsic { name, .. } if name == "rep_loop_enter"))
        );
        assert!(
            effs.iter()
                .any(|e| matches!(e, Effect::Intrinsic { name, .. } if name == "rep_loop_exit"))
        );
    }

    // CMPS
    #[test]
    fn cmps_reads_both_sides() {
        let lft = StringOpLifter::new(ctx64());
        let effs = lft.lift("cmps");
        assert_eq!(
            effs.iter()
                .filter(|e| matches!(e, Effect::MemRead { .. }))
                .count(),
            2
        );
    }

    #[test]
    fn cmps_sets_zf() {
        let lft = StringOpLifter::new(ctx64());
        let effs = lft.lift("cmps");
        assert!(
            effs.iter()
                .any(|e| matches!(e, Effect::RegWrite { reg, .. } if reg == "zf"))
        );
    }

    // SCAS
    #[test]
    fn scas_reads_rdi_only() {
        let lft = StringOpLifter::new(ctx64());
        let effs = lft.lift("scas");
        assert!(effs.iter().any(|e| matches!(e, Effect::MemRead { .. })));
        assert!(
            effs.iter()
                .any(|e| matches!(e, Effect::RegWrite { reg, .. } if reg == "zf"))
        );
    }

    // LODS
    #[test]
    fn lods_writes_rax() {
        let lft = StringOpLifter::new(ctx64());
        let effs = lft.lift("lods");
        assert!(
            effs.iter()
                .any(|e| matches!(e, Effect::MemRead { dest, .. } if dest == "rax"))
        );
    }

    // STOS
    #[test]
    fn stos_writes_mem() {
        let lft = StringOpLifter::new(ctx64());
        let effs = lft.lift("stos");
        assert!(effs.iter().any(|e| matches!(e, Effect::MemWrite { .. })));
    }

    #[test]
    fn stos_byte_uses_al() {
        let mut ctx = ctx64();
        ctx.op_size = 1;
        let lft = StringOpLifter::new(ctx);
        let effs = lft.lift("stos");
        assert!(
            effs.iter()
                .any(|e| matches!(e, Effect::MemWrite { value: IrExpr::Reg(r), .. } if r == "al"))
        );
    }

    // INS
    #[test]
    fn ins_emits_io_read_and_mem_write() {
        let lft = StringOpLifter::new(ctx64());
        let effs = lft.lift("ins");
        assert!(
            effs.iter()
                .any(|e| matches!(e, Effect::Intrinsic { name, .. } if name == "io_read"))
        );
        assert!(effs.iter().any(|e| matches!(e, Effect::MemWrite { .. })));
    }

    // OUTS
    #[test]
    fn outs_emits_io_write_and_mem_read() {
        let lft = StringOpLifter::new(ctx64());
        let effs = lft.lift("outs");
        assert!(effs.iter().any(|e| matches!(e, Effect::MemRead { .. })));
        assert!(
            effs.iter()
                .any(|e| matches!(e, Effect::Intrinsic { name, .. } if name == "io_write"))
        );
    }

    // Direction flag — down
    #[test]
    fn movs_down_decrements_pointers() {
        let lft = StringOpLifter::new(ctx64().std());
        let effs = lft.lift("movs");
        let decrements = effs.iter().filter(|e| matches!(
            e, Effect::RegWrite { value: IrExpr::Sub(..), reg } if reg == "rsi" || reg == "rdi"
        )).count();
        assert_eq!(decrements, 2);
    }

    // Unknown DF
    #[test]
    fn movs_unknown_df_emits_advance_intrinsic() {
        let mut ctx = ctx64();
        ctx.df = DirectionFlag::Unknown;
        let lft = StringOpLifter::new(ctx);
        let effs = lft.lift("movs");
        assert!(
            effs.iter()
                .any(|e| matches!(e, Effect::Intrinsic { name, .. } if name == "advance_ptr_df"))
        );
    }

    // Byte suffix stripped
    #[test]
    fn movsb_treated_as_movs() {
        let mut ctx = ctx64();
        ctx.op_size = 1;
        let lft = StringOpLifter::new(ctx);
        let effs = lft.lift("movsb");
        assert!(effs.iter().any(|e| matches!(e, Effect::MemRead { .. })));
    }

    // 32-bit REPNE CMPS
    #[test]
    fn repne_cmps32_has_loop_and_zf() {
        let lft = StringOpLifter::new(ctx32().with_repne());
        let effs = lft.lift("cmps");
        assert!(
            effs.iter()
                .any(|e| matches!(e, Effect::Intrinsic { name, .. } if name == "rep_loop_enter"))
        );
        assert!(
            effs.iter()
                .any(|e| matches!(e, Effect::RegWrite { reg, .. } if reg == "zf"))
        );
    }
}
