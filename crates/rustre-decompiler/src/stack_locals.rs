//! Stack-local recovery — Gap E.
//!
//! Public-facing helpers built on top of [`crate::variable_recovery_engine`]
//! that name `[rsp+K]` / `[rbp-K]` accesses as monotonic `var_N` locals,
//! widen each slot per observed access width, detect struct-on-stack
//! candidates from heterogeneous accesses, and hide
//! `sub rsp,N` / `add rsp,N` / `push rbp` / `pop rbp` prologue/epilogue
//! instructions from emitted pseudo-C.

use std::collections::HashMap;
use std::ops::Range;

use crate::signature_recovery::{InstructionView, StackFrame as SigStackFrame, analyze_stack_frame};
use crate::variable_recovery_engine::{
    StructOnStackCandidate, VarKind, VarStorage, VariableRecoveryEngine,
};

/// A named stack local recovered from instruction-level accesses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StackLocal {
    /// Auto-assigned name: `var_0`, `var_1`, …
    pub name: String,
    /// Signed offset from the frame base.
    pub offset: i64,
    /// Widest observed access size in bytes.
    pub max_width: u32,
    /// Distinct access widths seen at this offset, sorted ascending.
    pub observed_widths: Vec<u32>,
    /// `"local"` or `"param"`.
    pub kind: &'static str,
}

/// Aggregated stack-frame report for a function — locals, struct candidates,
/// prologue / epilogue ranges, and frame size.
#[derive(Debug, Clone, Default)]
pub struct StackFrameReport {
    /// Detected total frame size in bytes (0 = unknown).
    pub frame_size: u32,
    /// Address range `[start, end)` of the prologue, or `None` if not
    /// detected.
    pub prologue: Option<Range<u64>>,
    /// Address range `[start, end)` of the epilogue, or `None` if not
    /// detected.
    pub epilogue: Option<Range<u64>>,
    /// All recovered stack locals, sorted by offset.
    pub locals: Vec<StackLocal>,
    /// Struct-on-stack candidates.
    pub struct_candidates: Vec<StructOnStackCandidate>,
    /// Names of callee-saved registers preserved by the prologue.
    pub saved_regs: Vec<String>,
}

/// Detect struct-on-stack candidates directly from a fully-driven engine.
#[must_use]
pub fn detect_struct_candidates(engine: &VariableRecoveryEngine) -> Vec<StructOnStackCandidate> {
    engine.struct_candidates()
}

/// Compute the address range `[start, end)` covered by the function's
/// prologue, based on the leading run of frame-setup instructions.
///
/// Empty range if no prologue is detected.
#[must_use]
pub fn mask_prologue<I: InstructionViewWithAddr>(insns: &[I]) -> Range<u64> {
    let mut start: Option<u64> = None;
    let mut end: Option<u64> = None;
    for ins in insns {
        let m = ins.mnemonic().to_ascii_lowercase();
        let ops = ins.operands().to_ascii_lowercase();
        let is_pro = matches!(m.as_str(), "push" | "endbr64" | "endbr32")
            || (m == "mov" && ops.starts_with("rbp,") && ops.contains("rsp"))
            || (m == "sub" && ops.starts_with("rsp,"));
        if is_pro {
            if start.is_none() {
                start = Some(ins.addr());
            }
            end = Some(ins.addr() + 1);
        } else {
            break;
        }
    }
    start.unwrap_or(0)..end.unwrap_or(0)
}

/// Compute the address range `[start, end)` covered by the function's
/// epilogue (the trailing `add rsp,N` / `pop` / `leave` / `ret` window).
#[must_use]
pub fn mask_epilogue<I: InstructionViewWithAddr>(insns: &[I]) -> Range<u64> {
    let mut start: Option<u64> = None;
    let mut end: Option<u64> = None;
    for ins in insns.iter().rev() {
        let m = ins.mnemonic().to_ascii_lowercase();
        let ops = ins.operands().to_ascii_lowercase();
        let is_epi = matches!(m.as_str(), "ret" | "retn" | "leave" | "pop")
            || (m == "add" && ops.starts_with("rsp,"));
        if is_epi {
            if end.is_none() {
                end = Some(ins.addr() + 1);
            }
            start = Some(ins.addr());
        } else {
            break;
        }
    }
    start.unwrap_or(0)..end.unwrap_or(0)
}

/// Build a [`StackFrameReport`] by combining a [`VariableRecoveryEngine`]
/// (already fed with stack accesses) with the prologue/epilogue analysis
/// from [`analyze_stack_frame`].
#[must_use]
pub fn build_report<I: InstructionViewWithAddr>(
    engine: &VariableRecoveryEngine,
    insns: &[I],
) -> StackFrameReport {
    let frame: SigStackFrame = analyze_stack_frame(insns);
    let renames: HashMap<i64, String> = engine
        .stack_locals_named()
        .into_iter()
        .map(|(off, name, _)| (off, name))
        .collect();

    let mut locals: Vec<StackLocal> = engine
        .vars()
        .iter()
        .filter_map(|v| match v.storage {
            VarStorage::StackOffset(o) => {
                let kind = match v.kind {
                    VarKind::StackParam => "param",
                    VarKind::StackLocal => "local",
                    _ => return None,
                };
                let widths: Vec<u32> = v.access_widths.iter().copied().collect();
                let name = renames.get(&o).cloned().unwrap_or_else(|| v.name.clone());
                let slot_width = engine
                    .stack_frame()
                    .slots
                    .get(&o)
                    .map_or(v.size, |s| s.max_width);
                Some(StackLocal {
                    name,
                    offset: o,
                    max_width: slot_width.max(v.size),
                    observed_widths: widths,
                    kind,
                })
            }
            _ => None,
        })
        .collect();
    locals.sort_by_key(|l| l.offset);

    let pro = mask_prologue(insns);
    let epi = mask_epilogue(insns);

    StackFrameReport {
        frame_size: frame.frame_size,
        prologue: if pro.start < pro.end { Some(pro) } else { None },
        epilogue: if epi.start < epi.end { Some(epi) } else { None },
        locals,
        struct_candidates: engine.struct_candidates(),
        saved_regs: frame.saved_regs,
    }
}

/// Trait extending [`InstructionView`] with an address so this module can
/// emit address ranges. Implementors are typically `(addr, mnem, ops)`
/// triples lifted from the disassembler.
pub trait InstructionViewWithAddr: InstructionView {
    /// Address of this instruction.
    fn addr(&self) -> u64;
}

/// Owned, plain-data implementation of [`InstructionViewWithAddr`] useful
/// for tests and MCP wiring.
#[derive(Debug, Clone)]
pub struct AddressedInsn {
    pub addr: u64,
    pub mnemonic: String,
    pub operands: String,
}

impl InstructionView for AddressedInsn {
    fn mnemonic(&self) -> &str { &self.mnemonic }
    fn operands(&self) -> &str { &self.operands }
    fn reads_register(&self, reg: &str) -> bool {
        let r = reg.to_ascii_lowercase();
        self.operands
            .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
            .any(|t| t.eq_ignore_ascii_case(&r))
    }
    fn writes_register(&self, reg: &str) -> bool {
        if let Some((dst, _)) = self.operands.split_once(',') {
            let r = reg.to_ascii_lowercase();
            dst.split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
                .any(|t| t.eq_ignore_ascii_case(&r))
        } else {
            false
        }
    }
}

impl InstructionViewWithAddr for AddressedInsn {
    fn addr(&self) -> u64 { self.addr }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::variable_recovery_engine::CallingConvention;

    fn ins(addr: u64, m: &str, ops: &str) -> AddressedInsn {
        AddressedInsn { addr, mnemonic: m.into(), operands: ops.into() }
    }

    #[test]
    fn prologue_range_detected() {
        let prog = vec![
            ins(0x1000, "push", "rbp"),
            ins(0x1001, "mov", "rbp, rsp"),
            ins(0x1004, "sub", "rsp, 0x20"),
            ins(0x1008, "mov", "[rbp-8], rdi"),
            ins(0x100c, "ret", ""),
        ];
        let pro = mask_prologue(&prog);
        assert_eq!(pro.start, 0x1000);
        assert_eq!(pro.end, 0x1005);
    }

    #[test]
    fn epilogue_range_detected() {
        let prog = vec![
            ins(0x1000, "push", "rbp"),
            ins(0x1001, "mov", "rbp, rsp"),
            ins(0x1004, "mov", "[rbp-8], rdi"),
            ins(0x1008, "add", "rsp, 0x20"),
            ins(0x100c, "pop", "rbp"),
            ins(0x100d, "ret", ""),
        ];
        let epi = mask_epilogue(&prog);
        assert_eq!(epi.start, 0x1008);
        assert_eq!(epi.end, 0x100e);
    }

    #[test]
    fn build_report_assembles_everything() {
        let prog = vec![
            ins(0x1000, "push", "rbp"),
            ins(0x1001, "mov", "rbp, rsp"),
            ins(0x1004, "sub", "rsp, 0x20"),
            ins(0x1008, "mov", "[rbp-8], rdi"),
            ins(0x100c, "ret", ""),
        ];
        let mut eng = VariableRecoveryEngine::new(CallingConvention::SysVAmd64);
        eng.record_stack_access(-8, 8, 0x1008, true);
        eng.record_stack_access(-16, 4, 0x100a, true);
        let rep = build_report(&eng, &prog);
        assert_eq!(rep.frame_size, 0x20);
        assert!(rep.prologue.is_some());
        assert_eq!(rep.locals.len(), 2);
        assert_eq!(rep.locals[0].name, "var_0");
        assert_eq!(rep.locals[1].name, "var_1");
    }

    #[test]
    fn struct_candidate_through_report() {
        let prog = vec![ins(0x1000, "ret", "")];
        let mut eng = VariableRecoveryEngine::new(CallingConvention::Generic);
        eng.record_stack_access(-32, 8, 0x1000, true);
        eng.record_stack_access(-32, 4, 0x1004, false);
        let rep = build_report(&eng, &prog);
        assert_eq!(rep.struct_candidates.len(), 1);
        assert_eq!(rep.struct_candidates[0].base_offset, -32);
    }
}
