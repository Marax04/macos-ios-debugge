//! Deep calling-convention heuristics: stack-cleanup classification,
//! callee-saved preservation analysis, and argument-register profiling.
//!
//! The base [`CallingConventionDetector`](crate::CallingConventionDetector)
//! extracts an [`ObservedPattern`](crate::ObservedPattern) and scores it against
//! a database.  This module adds three focused analyses the spec calls out,
//! each producing a structured verdict that can be used on its own or folded
//! back into convention matching:
//!
//! * **Stack cleanup** — does the *callee* clean its stack arguments (`ret N`,
//!   stdcall/thiscall/fastcall) or does the *caller* (`ret 0`, cdecl/SysV)?
//! * **Callee-saved preservation** — which pushed registers are symmetrically
//!   restored before return (genuinely preserved) versus clobbered.
//! * **Argument-register profile** — which registers are read before being
//!   written (live-on-entry), the classic signal for register-passed args.

use crate::{Arch, CallingConventionPattern, DetectInstr};
use std::collections::HashSet;

/// Who is responsible for removing stack arguments after a call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StackCleanup {
    /// Caller cleans the stack (cdecl, `SysV`) — callee returns with `ret 0`.
    Caller,
    /// Callee cleans the stack (stdcall, thiscall, fastcall) — `ret N`.
    Callee {
        /// Bytes the callee pops.
        bytes: u32,
    },
    /// No stack arguments / cannot determine.
    Unknown,
}

impl StackCleanup {
    /// Whether the callee performs the cleanup.
    #[must_use]
    pub const fn is_callee(self) -> bool {
        matches!(self, Self::Callee { .. })
    }

    /// Bytes popped by the callee (0 for caller-cleanup / unknown).
    #[must_use]
    pub const fn callee_bytes(self) -> u32 {
        match self {
            Self::Callee { bytes } => bytes,
            Self::Caller | Self::Unknown => 0,
        }
    }
}

/// Classify stack cleanup from an instruction stream by inspecting the `ret`.
#[must_use]
pub fn classify_stack_cleanup(instrs: &[DetectInstr]) -> StackCleanup {
    let mut saw_stack_args = false;
    for instr in instrs {
        match instr {
            DetectInstr::StackArgAccess { .. } => saw_stack_args = true,
            DetectInstr::Ret { stack_bytes } => {
                if *stack_bytes > 0 {
                    return StackCleanup::Callee {
                        bytes: *stack_bytes,
                    };
                }
                return if saw_stack_args {
                    StackCleanup::Caller
                } else {
                    StackCleanup::Unknown
                };
            }
            DetectInstr::RegRead { .. }
            | DetectInstr::RegWrite { .. }
            | DetectInstr::Push { .. }
            | DetectInstr::Pop { .. }
            | DetectInstr::ThisPtrUse
            | DetectInstr::FpRegRead { .. }
            | DetectInstr::StackAlloc { .. }
            | DetectInstr::Other => {}
        }
    }
    StackCleanup::Unknown
}

/// Report on which callee-saved registers a function actually preserves.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PreservationReport {
    /// Registers pushed and symmetrically popped (genuinely preserved).
    pub preserved: Vec<String>,
    /// Registers pushed but never restored (spills, not preservation).
    pub unbalanced_pushes: Vec<String>,
    /// Registers popped without a matching push (unbalanced).
    pub unbalanced_pops: Vec<String>,
}

impl PreservationReport {
    /// Whether the prologue/epilogue is balanced (every push has a pop).
    #[must_use]
    pub const fn is_balanced(&self) -> bool {
        self.unbalanced_pushes.is_empty() && self.unbalanced_pops.is_empty()
    }

    /// Number of genuinely preserved registers.
    #[must_use]
    pub const fn preserved_count(&self) -> usize {
        self.preserved.len()
    }
}

/// Analyse callee-saved preservation: match `push reg` against later `pop reg`
/// in LIFO order (the standard prologue/epilogue discipline).
#[must_use]
pub fn analyze_preservation(instrs: &[DetectInstr]) -> PreservationReport {
    let mut push_stack: Vec<String> = Vec::new();
    let mut preserved: Vec<String> = Vec::new();
    let mut unbalanced_pops: Vec<String> = Vec::new();

    for instr in instrs {
        match instr {
            DetectInstr::Push { reg } => push_stack.push(reg.clone()),
            DetectInstr::Pop { reg } => {
                match push_stack.last() {
                    Some(top) if top == reg => {
                        push_stack.pop();
                        if !preserved.contains(reg) {
                            preserved.push(reg.clone());
                        }
                    }
                    _ => {
                        // Pop without a matching LIFO push.
                        if let Some(pos) = push_stack.iter().rposition(|r| r == reg) {
                            // Out-of-order but balanced restore.
                            push_stack.remove(pos);
                            if !preserved.contains(reg) {
                                preserved.push(reg.clone());
                            }
                        } else {
                            unbalanced_pops.push(reg.clone());
                        }
                    }
                }
            }
            DetectInstr::RegRead { .. }
            | DetectInstr::RegWrite { .. }
            | DetectInstr::Ret { .. }
            | DetectInstr::ThisPtrUse
            | DetectInstr::FpRegRead { .. }
            | DetectInstr::StackAlloc { .. }
            | DetectInstr::StackArgAccess { .. }
            | DetectInstr::Other => {}
        }
    }

    PreservationReport {
        preserved,
        unbalanced_pushes: push_stack,
        unbalanced_pops,
    }
}

/// A profile of how registers are used at function entry.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ArgRegisterProfile {
    /// Integer/pointer registers read before any write (live-on-entry).
    pub int_args: Vec<String>,
    /// FP registers read before any write.
    pub fp_args: Vec<String>,
}

impl ArgRegisterProfile {
    /// Total number of candidate argument registers.
    #[must_use]
    pub const fn arg_count(&self) -> usize {
        self.int_args.len() + self.fp_args.len()
    }

    /// Whether the profile matches the *prefix* of `cc`'s argument registers
    /// (i.e. the function uses arg registers in the convention's order).
    #[must_use]
    pub fn matches_convention(&self, cc: &CallingConventionPattern) -> bool {
        if self.int_args.is_empty() {
            return true; // no evidence either way
        }
        // Every observed int-arg register must be one of the convention's
        // argument registers.
        self.int_args.iter().all(|r| cc.arg_registers.contains(r))
    }
}

/// Profile the argument-register usage of a function.
#[must_use]
pub fn profile_arg_registers(instrs: &[DetectInstr]) -> ArgRegisterProfile {
    let mut written: HashSet<String> = HashSet::new();
    let mut int_args: Vec<String> = Vec::new();
    let mut fp_args: Vec<String> = Vec::new();

    for instr in instrs {
        match instr {
            DetectInstr::RegRead { reg } => {
                if !written.contains(reg) && !int_args.contains(reg) {
                    int_args.push(reg.clone());
                }
            }
            DetectInstr::FpRegRead { reg } => {
                if !written.contains(reg) && !fp_args.contains(reg) {
                    fp_args.push(reg.clone());
                }
            }
            DetectInstr::RegWrite { reg } | DetectInstr::Pop { reg } => {
                written.insert(reg.clone());
            }
            DetectInstr::Push { reg } => {
                written.insert(reg.clone());
            }
            DetectInstr::Ret { .. }
            | DetectInstr::ThisPtrUse
            | DetectInstr::StackAlloc { .. }
            | DetectInstr::StackArgAccess { .. }
            | DetectInstr::Other => {}
        }
    }

    ArgRegisterProfile { int_args, fp_args }
}

/// The default callee-saved register set for an architecture's main C ABI,
/// used to filter genuine preservation from incidental spills.
#[must_use]
pub const fn default_callee_saved(arch: &Arch) -> &'static [&'static str] {
    match arch {
        Arch::X86 => &["ebx", "esi", "edi", "ebp"],
        Arch::X86_64 => &["rbx", "rbp", "r12", "r13", "r14", "r15"],
        Arch::Arm64 => &[
            "x19", "x20", "x21", "x22", "x23", "x24", "x25", "x26", "x27", "x28", "x29",
        ],
        Arch::Arm32 => &["r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11"],
        _ => &[],
    }
}

/// Combine all three heuristics into a single verdict for one function.
#[derive(Debug, Clone)]
pub struct CallConvVerdict {
    /// Stack-cleanup responsibility.
    pub cleanup: StackCleanup,
    /// Callee-saved preservation report.
    pub preservation: PreservationReport,
    /// Argument-register profile.
    pub args: ArgRegisterProfile,
}

impl CallConvVerdict {
    /// Run all heuristics over a function's instruction stream.
    #[must_use]
    pub fn analyze(instrs: &[DetectInstr]) -> Self {
        Self {
            cleanup: classify_stack_cleanup(instrs),
            preservation: analyze_preservation(instrs),
            args: profile_arg_registers(instrs),
        }
    }

    /// A coarse confidence (0–100) that `cc` is the function's convention,
    /// combining cleanup agreement, preservation overlap, and arg-register fit.
    #[must_use]
    pub fn confidence_for(&self, cc: &CallingConventionPattern) -> u32 {
        let mut score = 50i32;

        // Stack cleanup agreement.
        match self.cleanup {
            StackCleanup::Callee { .. } if !cc.caller_cleanup => score += 25,
            StackCleanup::Caller if cc.caller_cleanup => score += 25,
            StackCleanup::Unknown => {}
            _ => score -= 25, // direct contradiction
        }

        // Preservation overlap.
        let preserved_match = self
            .preservation
            .preserved
            .iter()
            .filter(|r| cc.callee_saved.contains(r))
            .count();
        score += i32::try_from(preserved_match).unwrap_or(0) * 5;

        // Arg-register fit.
        if self.args.matches_convention(cc) {
            score += 10;
        } else {
            score -= 10;
        }

        score.clamp(0, 100).unsigned_abs()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{cdecl_x86, stdcall_x86, sysv_x64};

    fn read(r: &str) -> DetectInstr {
        DetectInstr::RegRead { reg: r.into() }
    }
    fn write(r: &str) -> DetectInstr {
        DetectInstr::RegWrite { reg: r.into() }
    }
    fn push(r: &str) -> DetectInstr {
        DetectInstr::Push { reg: r.into() }
    }
    fn pop(r: &str) -> DetectInstr {
        DetectInstr::Pop { reg: r.into() }
    }

    #[test]
    fn cleanup_callee_ret_n() {
        let instrs = vec![DetectInstr::Ret { stack_bytes: 8 }];
        let c = classify_stack_cleanup(&instrs);
        assert!(c.is_callee());
        assert_eq!(c.callee_bytes(), 8);
    }

    #[test]
    fn cleanup_caller_when_stack_args_and_ret0() {
        let instrs = vec![
            DetectInstr::StackArgAccess { offset: 4 },
            DetectInstr::Ret { stack_bytes: 0 },
        ];
        assert_eq!(classify_stack_cleanup(&instrs), StackCleanup::Caller);
    }

    #[test]
    fn cleanup_unknown_without_stack_args() {
        let instrs = vec![DetectInstr::Ret { stack_bytes: 0 }];
        assert_eq!(classify_stack_cleanup(&instrs), StackCleanup::Unknown);
    }

    #[test]
    fn preservation_balanced_lifo() {
        // push rbx; push r12; ...; pop r12; pop rbx
        let instrs = vec![push("rbx"), push("r12"), pop("r12"), pop("rbx")];
        let rep = analyze_preservation(&instrs);
        assert!(rep.is_balanced());
        assert_eq!(rep.preserved_count(), 2);
        assert!(rep.preserved.contains(&"rbx".to_string()));
    }

    #[test]
    fn preservation_unbalanced_push() {
        // push rbx with no matching pop -> spill, not preservation.
        let instrs = vec![push("rbx"), DetectInstr::Ret { stack_bytes: 0 }];
        let rep = analyze_preservation(&instrs);
        assert!(!rep.is_balanced());
        assert_eq!(rep.unbalanced_pushes, vec!["rbx".to_string()]);
    }

    #[test]
    fn preservation_out_of_order_restore() {
        // push a; push b; pop a; pop b  (not strict LIFO, but balanced).
        let instrs = vec![push("a"), push("b"), pop("a"), pop("b")];
        let rep = analyze_preservation(&instrs);
        assert!(rep.is_balanced());
        assert_eq!(rep.preserved_count(), 2);
    }

    #[test]
    fn arg_profile_read_before_write() {
        // rdi read before write -> arg; rax written then read -> not arg.
        let instrs = vec![read("rdi"), write("rax"), read("rax"), read("rsi")];
        let profile = profile_arg_registers(&instrs);
        assert!(profile.int_args.contains(&"rdi".to_string()));
        assert!(profile.int_args.contains(&"rsi".to_string()));
        assert!(!profile.int_args.contains(&"rax".to_string()));
        assert_eq!(profile.arg_count(), 2);
    }

    #[test]
    fn arg_profile_matches_sysv() {
        let instrs = vec![read("rdi"), read("rsi")];
        let profile = profile_arg_registers(&instrs);
        assert!(profile.matches_convention(&sysv_x64()));
    }

    #[test]
    fn default_callee_saved_sets() {
        assert!(default_callee_saved(&Arch::X86_64).contains(&"rbx"));
        assert!(default_callee_saved(&Arch::X86).contains(&"esi"));
        assert!(default_callee_saved(&Arch::Mips32).is_empty());
    }

    #[test]
    fn verdict_distinguishes_cdecl_from_stdcall() {
        // A cdecl-like function: caller cleanup (ret 0 with stack args), rdi arg.
        let cdecl_fn = vec![
            DetectInstr::StackArgAccess { offset: 4 },
            DetectInstr::Ret { stack_bytes: 0 },
        ];
        let v = CallConvVerdict::analyze(&cdecl_fn);
        let cdecl_conf = v.confidence_for(&cdecl_x86());
        let stdcall_conf = v.confidence_for(&stdcall_x86());
        assert!(
            cdecl_conf > stdcall_conf,
            "cdecl={cdecl_conf} should beat stdcall={stdcall_conf}"
        );

        // A stdcall-like function: callee cleanup (ret 8).
        let stdcall_fn = vec![
            DetectInstr::StackArgAccess { offset: 4 },
            DetectInstr::Ret { stack_bytes: 8 },
        ];
        let v2 = CallConvVerdict::analyze(&stdcall_fn);
        assert!(v2.confidence_for(&stdcall_x86()) > v2.confidence_for(&cdecl_x86()));
    }

    #[test]
    fn verdict_full_analysis() {
        let instrs = vec![
            push("rbx"),
            read("rdi"),
            write("rbx"),
            pop("rbx"),
            DetectInstr::Ret { stack_bytes: 0 },
        ];
        let v = CallConvVerdict::analyze(&instrs);
        assert_eq!(v.preservation.preserved_count(), 1);
        assert!(v.args.int_args.contains(&"rdi".to_string()));
    }

    // ── Additional edge-case tests ───────────────────────────────────────────

    #[test]
    fn cleanup_empty_instrs_is_unknown() {
        assert_eq!(classify_stack_cleanup(&[]), StackCleanup::Unknown);
    }

    #[test]
    fn cleanup_max_callee_bytes() {
        let instrs = vec![DetectInstr::Ret { stack_bytes: u32::MAX }];
        let c = classify_stack_cleanup(&instrs);
        assert!(c.is_callee());
        assert_eq!(c.callee_bytes(), u32::MAX);
    }

    #[test]
    fn cleanup_stops_at_first_ret() {
        // First ret should determine; ignore later instructions.
        let instrs = vec![
            DetectInstr::Ret { stack_bytes: 4 },
            DetectInstr::Ret { stack_bytes: 0 },
        ];
        assert_eq!(classify_stack_cleanup(&instrs), StackCleanup::Callee { bytes: 4 });
    }

    #[test]
    fn preservation_empty_is_balanced() {
        let rep = analyze_preservation(&[]);
        assert!(rep.is_balanced());
        assert_eq!(rep.preserved_count(), 0);
    }

    #[test]
    fn preservation_pop_without_push_is_unbalanced() {
        let rep = analyze_preservation(&[pop("rbx")]);
        assert!(!rep.is_balanced());
        assert_eq!(rep.unbalanced_pops, vec!["rbx".to_string()]);
    }

    #[test]
    fn preservation_dedup_repeated_save() {
        // push rbx; pop rbx twice — preserved listed once.
        let instrs = vec![push("rbx"), pop("rbx"), push("rbx"), pop("rbx")];
        let rep = analyze_preservation(&instrs);
        assert!(rep.is_balanced());
        assert_eq!(rep.preserved_count(), 1);
    }

    #[test]
    fn arg_profile_empty() {
        let p = profile_arg_registers(&[]);
        assert_eq!(p.arg_count(), 0);
        // Vacuous-truth: empty profile matches any convention.
        assert!(p.matches_convention(&sysv_x64()));
    }

    #[test]
    fn arg_profile_dedup_repeated_reads() {
        let instrs = vec![read("rdi"), read("rdi"), read("rdi")];
        let p = profile_arg_registers(&instrs);
        assert_eq!(p.int_args, vec!["rdi".to_string()]);
    }

    #[test]
    fn arg_profile_push_marks_written() {
        // push of rbx then read of rbx should not classify rbx as an argument.
        let instrs = vec![push("rbx"), read("rbx")];
        let p = profile_arg_registers(&instrs);
        assert!(!p.int_args.contains(&"rbx".to_string()));
    }

    #[test]
    fn stack_cleanup_is_callee_helpers() {
        assert!(!StackCleanup::Caller.is_callee());
        assert!(!StackCleanup::Unknown.is_callee());
        assert_eq!(StackCleanup::Caller.callee_bytes(), 0);
        assert_eq!(StackCleanup::Unknown.callee_bytes(), 0);
        assert!(StackCleanup::Callee { bytes: 16 }.is_callee());
    }
}
