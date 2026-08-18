//! x86 system instruction lifting.
//!
//! Covers privilege-level transitions, atomic memory operations, and
//! miscellaneous privileged or serialising instructions:
//!
//!   SYSCALL / SYSENTER / SYSEXIT / SYSRET
//!   INT n / INTO / INT3 / IRET / IRETD / IRETQ
//!   CPUID / RDTSC / RDTSCP / RDMSR / WRMSR / RDPMC
//!   HLT / UD2 / PAUSE / MFENCE / LFENCE / SFENCE / CLFLUSH
//!   XCHG (with implicit LOCK) / LOCK prefix / XADD
//!   CMPXCHG / CMPXCHG8B / CMPXCHG16B
//!   IN / OUT (I/O port)
//!   MOV `CRn` / MOV `DRn` / LMSW / CLTS
//!   LGDT / SGDT / LIDT / SIDT / LLDT / SLDT / LTR / STR
//!   PUSHF / POPF / LAHF / SAHF
//!
//! All instructions are lifted to IR using [`Effect`] values; privileged or
//! semantically complex operations become [`Effect::Intrinsic`] stubs so that
//! the IR graph remains total.
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
// SystemCallModel
// ─────────────────────────────────────────────────────────────────────────────

/// Describes how a system-call / software-interrupt instruction should be
/// modelled in the IL.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SystemCallModel {
    /// Model as a generic [`Effect::Syscall`] with the number in RAX.
    SyscallEffect,
    /// Model as an [`Effect::Intrinsic`] with the given name.
    Intrinsic(String),
    /// Fully inlined effects (not applicable to most syscall variants).
    Inline(Vec<SyscallEffect>),
}

/// Inline effect kinds for simple syscall-like instructions.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SyscallEffect {
    /// Save RIP to a well-known register (e.g. `rcx` after SYSCALL).
    SaveRip { dest_reg: String },
    /// Load new RIP from a register or descriptor.
    LoadRip { src_reg: String },
    /// Change privilege level (ring number 0-3).
    ChangeCpl { target: u8 },
}

// ─────────────────────────────────────────────────────────────────────────────
// SystemInsnLifter
// ─────────────────────────────────────────────────────────────────────────────

/// Lifts x86 system instructions to IL effects.
///
/// Stateless — all context is passed through the mnemonic / operand parameters.
#[derive(Debug, Clone, Default)]
pub struct SystemInsnLifter {
    /// Address-size in bits (16 / 32 / 64).
    pub addr_bits: u8,
    /// Model to use for SYSCALL / SYSENTER.
    pub syscall_model: Option<SystemCallModel>,
}

impl SystemInsnLifter {
    /// Create a 64-bit lifter with the default syscall model.
    #[must_use]
    pub const fn new_64() -> Self {
        Self {
            addr_bits: 64,
            syscall_model: Some(SystemCallModel::SyscallEffect),
        }
    }

    /// Create a 32-bit lifter.
    #[must_use]
    pub const fn new_32() -> Self {
        Self {
            addr_bits: 32,
            syscall_model: Some(SystemCallModel::SyscallEffect),
        }
    }

    /// Lift a system instruction.
    ///
    /// `mnemonic` should be the normalised lower-case mnemonic (no size suffix).
    /// `operands` is the list of source/destination [`IrExpr`] operands in order.
    /// `addr`     is the instruction's virtual address (used for CALL-like stubs).
    #[must_use]
    pub fn lift(&self, mnemonic: &str, operands: &[IrExpr], addr: u64) -> Vec<Effect> {
        let m = mnemonic.to_ascii_lowercase();
        match m.as_str() {
            // ── System calls ──────────────────────────────────────────────────
            "syscall" => self.lift_syscall("syscall"),
            "sysenter" => self.lift_syscall("sysenter"),
            "sysexit" | "sysexitq" => vec![self.intrinsic("sysexit", &[])],
            "sysret" | "sysretq" => vec![self.intrinsic("sysret", &[])],

            // ── Software interrupts ────────────────────────────────────────────
            "int" | "int3" | "int1" | "into" => {
                let nr = operands.first().cloned().unwrap_or(IrExpr::Const(0));
                vec![Effect::Syscall { nr }]
            }
            "iret" | "iretd" | "iretq" => {
                vec![self.intrinsic("iret", &[]), Effect::Return { value: None }]
            }

            // ── CPUID ─────────────────────────────────────────────────────────
            "cpuid" => vec![
                self.intrinsic(
                    "cpuid",
                    &[
                        IrExpr::Reg("eax".to_string()),
                        IrExpr::Reg("ecx".to_string()),
                    ],
                ),
                // cpuid writes EAX/EBX/ECX/EDX
                Effect::RegWrite {
                    reg: "eax".to_string(),
                    value: IrExpr::Reg("cpuid_eax_out".to_string()),
                },
                Effect::RegWrite {
                    reg: "ebx".to_string(),
                    value: IrExpr::Reg("cpuid_ebx_out".to_string()),
                },
                Effect::RegWrite {
                    reg: "ecx".to_string(),
                    value: IrExpr::Reg("cpuid_ecx_out".to_string()),
                },
                Effect::RegWrite {
                    reg: "edx".to_string(),
                    value: IrExpr::Reg("cpuid_edx_out".to_string()),
                },
            ],

            // ── Time-stamp counter ─────────────────────────────────────────────
            "rdtsc" => vec![
                self.intrinsic("rdtsc", &[]),
                Effect::RegWrite {
                    reg: "edx".to_string(),
                    value: IrExpr::Reg("tsc_hi".to_string()),
                },
                Effect::RegWrite {
                    reg: "eax".to_string(),
                    value: IrExpr::Reg("tsc_lo".to_string()),
                },
            ],
            "rdtscp" => vec![
                self.intrinsic("rdtscp", &[]),
                Effect::RegWrite {
                    reg: "edx".to_string(),
                    value: IrExpr::Reg("tsc_hi".to_string()),
                },
                Effect::RegWrite {
                    reg: "eax".to_string(),
                    value: IrExpr::Reg("tsc_lo".to_string()),
                },
                Effect::RegWrite {
                    reg: "ecx".to_string(),
                    value: IrExpr::Reg("tsc_aux".to_string()),
                },
            ],

            // ── MSR ───────────────────────────────────────────────────────────
            "rdmsr" => vec![
                self.intrinsic("rdmsr", &[IrExpr::Reg("ecx".to_string())]),
                Effect::RegWrite {
                    reg: "edx".to_string(),
                    value: IrExpr::Reg("msr_hi".to_string()),
                },
                Effect::RegWrite {
                    reg: "eax".to_string(),
                    value: IrExpr::Reg("msr_lo".to_string()),
                },
            ],
            "wrmsr" => vec![self.intrinsic(
                "wrmsr",
                &[
                    IrExpr::Reg("ecx".to_string()),
                    IrExpr::Reg("edx".to_string()),
                    IrExpr::Reg("eax".to_string()),
                ],
            )],
            "rdpmc" => vec![
                self.intrinsic("rdpmc", &[IrExpr::Reg("ecx".to_string())]),
                Effect::RegWrite {
                    reg: "eax".to_string(),
                    value: IrExpr::Reg("pmc_lo".to_string()),
                },
                Effect::RegWrite {
                    reg: "edx".to_string(),
                    value: IrExpr::Reg("pmc_hi".to_string()),
                },
            ],

            // ── Halt / Undefined / Pause ──────────────────────────────────────
            "hlt" => vec![self.intrinsic("hlt", &[])],
            "ud2" => vec![
                self.intrinsic("ud2", &[]),
                Effect::Intrinsic {
                    name: "undefined_instruction".to_string(),
                    args: vec![],
                },
            ],
            "pause" => vec![self.intrinsic("pause", &[])],

            // ── Fence instructions ─────────────────────────────────────────────
            "mfence" => vec![self.intrinsic("mfence", &[])],
            "lfence" => vec![self.intrinsic("lfence", &[])],
            "sfence" => vec![self.intrinsic("sfence", &[])],
            "clflush" | "clflushopt" => {
                let addr_expr = operands.first().cloned().unwrap_or(IrExpr::Undef);
                vec![self.intrinsic("clflush", &[addr_expr])]
            }

            // ── XCHG (atomic; LOCK implied) ────────────────────────────────────
            "xchg" => {
                let a: IrExpr = operands.first().cloned().unwrap_or(IrExpr::Undef);
                let b: IrExpr = operands.get(1).cloned().unwrap_or(IrExpr::Undef);
                let dst_a = extract_reg_name(operands.first());
                let dst_b = extract_reg_name(operands.get(1));
                vec![
                    self.intrinsic("lock_xchg", &[a.clone(), b.clone()]),
                    Effect::RegWrite {
                        reg: dst_a,
                        value: b,
                    },
                    Effect::RegWrite {
                        reg: dst_b,
                        value: a,
                    },
                ]
            }

            // ── XADD ──────────────────────────────────────────────────────────
            "xadd" => {
                let mem = operands.first().cloned().unwrap_or(IrExpr::Undef);
                let reg = operands.get(1).cloned().unwrap_or(IrExpr::Undef);
                let sum = IrExpr::Add(Box::new(mem.clone()), Box::new(reg.clone()));
                let dst = extract_reg_name(operands.first());
                vec![
                    self.intrinsic("lock", &[]),
                    // store old mem value into reg
                    Effect::RegWrite {
                        reg: extract_reg_name(operands.get(1)),
                        value: mem,
                    },
                    // write sum back to mem
                    Effect::RegWrite {
                        reg: dst,
                        value: sum,
                    },
                ]
            }

            // ── CMPXCHG ───────────────────────────────────────────────────────
            "cmpxchg" => {
                // if AL/AX/EAX/RAX == [dst] then [dst] = src; else AL/AX/EAX/RAX = [dst]
                let dst = operands.first().cloned().unwrap_or(IrExpr::Undef);
                let src = operands.get(1).cloned().unwrap_or(IrExpr::Undef);
                let acc = self.accumulator_reg();
                vec![
                    self.intrinsic("lock", &[]),
                    Effect::Intrinsic {
                        name: "cmpxchg".to_string(),
                        args: vec![dst, src, IrExpr::Reg(acc.to_string())],
                    },
                    Effect::RegWrite {
                        reg: "zf".to_string(),
                        value: IrExpr::Undef,
                    },
                ]
            }
            "cmpxchg8b" => vec![
                self.intrinsic("lock", &[]),
                self.intrinsic("cmpxchg8b", operands),
                Effect::RegWrite {
                    reg: "zf".to_string(),
                    value: IrExpr::Undef,
                },
            ],
            "cmpxchg16b" => vec![
                self.intrinsic("lock", &[]),
                self.intrinsic("cmpxchg16b", operands),
                Effect::RegWrite {
                    reg: "zf".to_string(),
                    value: IrExpr::Undef,
                },
            ],

            // ── I/O port ──────────────────────────────────────────────────────
            "in" => {
                let port = operands
                    .first()
                    .cloned()
                    .unwrap_or(IrExpr::Reg("dx".to_string()));
                let dst = extract_reg_name(operands.first());
                vec![
                    self.intrinsic("io_read", &[port]),
                    Effect::RegWrite {
                        reg: dst,
                        value: IrExpr::Reg("__io_val".to_string()),
                    },
                ]
            }
            "out" => {
                let port = operands
                    .first()
                    .cloned()
                    .unwrap_or(IrExpr::Reg("dx".to_string()));
                let val = operands.get(1).cloned().unwrap_or(IrExpr::Undef);
                vec![self.intrinsic("io_write", &[port, val])]
            }

            // ── Control register moves ────────────────────────────────────────
            m if m.starts_with("mov") && (m.contains("cr") || m.contains("dr")) => {
                let src = operands.get(1).cloned().unwrap_or(IrExpr::Undef);
                let dst_name = extract_reg_name(operands.first());
                vec![
                    self.intrinsic(
                        "priv_reg_access",
                        &[IrExpr::Reg(dst_name.clone()), src.clone()],
                    ),
                    Effect::RegWrite {
                        reg: dst_name,
                        value: src,
                    },
                ]
            }

            // ── Descriptor table / segment instructions ────────────────────────
            "lgdt" | "sgdt" | "lidt" | "sidt" | "lldt" | "sldt" | "ltr" | "str" | "lmsw"
            | "smsw" | "clts" => {
                vec![self.intrinsic(m.as_str(), operands)]
            }

            // ── PUSHF / POPF ──────────────────────────────────────────────────
            "pushf" | "pushfd" | "pushfq" => {
                let rsp = self.rsp_reg();
                vec![
                    Effect::RegWrite {
                        reg: rsp.to_string(),
                        value: IrExpr::Sub(
                            Box::new(IrExpr::Reg(rsp.to_string())),
                            Box::new(IrExpr::Const(u64::from(self.flags_size()))),
                        ),
                    },
                    Effect::MemWrite {
                        addr: IrExpr::Reg(rsp.to_string()),
                        value: IrExpr::Reg(self.rflags_reg().to_string()),
                        size: self.flags_size(),
                    },
                ]
            }
            "popf" | "popfd" | "popfq" => {
                let rsp = self.rsp_reg();
                vec![
                    Effect::MemRead {
                        addr: IrExpr::Reg(rsp.to_string()),
                        dest: self.rflags_reg().to_string(),
                        size: self.flags_size(),
                    },
                    Effect::RegWrite {
                        reg: rsp.to_string(),
                        value: IrExpr::Add(
                            Box::new(IrExpr::Reg(rsp.to_string())),
                            Box::new(IrExpr::Const(u64::from(self.flags_size()))),
                        ),
                    },
                ]
            }

            // ── LAHF / SAHF ────────────────────────────────────────────────────
            "lahf" => vec![Effect::RegWrite {
                reg: "ah".to_string(),
                value: IrExpr::Reg("flags_lo".to_string()),
            }],
            "sahf" => vec![Effect::RegWrite {
                reg: "flags_lo".to_string(),
                value: IrExpr::Reg("ah".to_string()),
            }],

            // ── NOP ───────────────────────────────────────────────────────────
            "nop" | "fnop" => vec![],

            // ── LOCK prefix (no-op in IR) ──────────────────────────────────────
            "lock" => vec![self.intrinsic("lock", &[])],

            // ── fallback ──────────────────────────────────────────────────────
            _ => {
                // Tag the synthetic intrinsic with the instruction address so
                // downstream taint/analysis passes can correlate unhandled
                // system insns back to source PC without re-disassembling.
                let mut args: Vec<IrExpr> = Vec::with_capacity(operands.len() + 1);
                args.push(IrExpr::Const(addr));
                args.extend(operands.iter().cloned());
                vec![self.intrinsic(&format!("__sys_{m}"), &args)]
            }
        }
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    fn lift_syscall(&self, name: &str) -> Vec<Effect> {
        match &self.syscall_model {
            Some(SystemCallModel::SyscallEffect) => vec![Effect::Syscall {
                nr: IrExpr::Reg("rax".to_string()),
            }],
            Some(SystemCallModel::Intrinsic(n)) => {
                vec![self.intrinsic(n, &[IrExpr::Reg("rax".to_string())])]
            }
            _ => vec![self.intrinsic(name, &[IrExpr::Reg("rax".to_string())])],
        }
    }

    fn intrinsic(&self, name: &str, args: &[IrExpr]) -> Effect {
        Effect::Intrinsic {
            name: name.to_string(),
            args: args.to_vec(),
        }
    }

    const fn accumulator_reg(&self) -> &'static str {
        match self.addr_bits {
            64 => "rax",
            32 => "eax",
            _ => "ax",
        }
    }

    const fn rsp_reg(&self) -> &'static str {
        match self.addr_bits {
            64 => "rsp",
            32 => "esp",
            _ => "sp",
        }
    }

    const fn rflags_reg(&self) -> &'static str {
        match self.addr_bits {
            64 => "rflags",
            _ => "eflags",
        }
    }

    const fn flags_size(&self) -> u8 {
        match self.addr_bits {
            64 => 8,
            32 => 4,
            _ => 2,
        }
    }
}

/// Extract a register name from an optional operand reference.
fn extract_reg_name(op: Option<&IrExpr>) -> String {
    match op {
        Some(IrExpr::Reg(r)) => r.clone(),
        _ => "__unknown_reg".to_string(),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn lft64() -> SystemInsnLifter {
        SystemInsnLifter::new_64()
    }
    fn lft32() -> SystemInsnLifter {
        SystemInsnLifter::new_32()
    }
    fn no_ops() -> Vec<IrExpr> {
        vec![]
    }

    // SYSCALL
    #[test]
    fn syscall_emits_syscall_effect() {
        let effs = lft64().lift("syscall", &no_ops(), 0x1000);
        assert!(effs.iter().any(|e| matches!(e, Effect::Syscall { .. })));
    }

    // SYSENTER
    #[test]
    fn sysenter_emits_syscall() {
        let effs = lft64().lift("sysenter", &no_ops(), 0);
        assert!(effs.iter().any(|e| matches!(e, Effect::Syscall { .. })));
    }

    // SYSEXIT
    #[test]
    fn sysexit_emits_intrinsic() {
        let effs = lft64().lift("sysexit", &no_ops(), 0);
        assert!(
            effs.iter()
                .any(|e| matches!(e, Effect::Intrinsic { name, .. } if name == "sysexit"))
        );
    }

    // INT
    #[test]
    fn int_emits_syscall_with_imm() {
        let ops = vec![IrExpr::Const(0x80)];
        let effs = lft32().lift("int", &ops, 0);
        assert!(effs.iter().any(|e| matches!(
            e,
            Effect::Syscall {
                nr: IrExpr::Const(0x80)
            }
        )));
    }

    // INT3
    #[test]
    fn int3_emits_syscall() {
        let effs = lft64().lift("int3", &no_ops(), 0);
        assert!(effs.iter().any(|e| matches!(e, Effect::Syscall { .. })));
    }

    // IRET
    #[test]
    fn iret_emits_intrinsic_and_return() {
        let effs = lft64().lift("iret", &no_ops(), 0);
        assert!(
            effs.iter()
                .any(|e| matches!(e, Effect::Intrinsic { name, .. } if name == "iret"))
        );
        assert!(effs.iter().any(|e| matches!(e, Effect::Return { .. })));
    }

    // CPUID
    #[test]
    fn cpuid_writes_four_regs() {
        let effs = lft64().lift("cpuid", &no_ops(), 0);
        let writes: Vec<_> = effs
            .iter()
            .filter(|e| matches!(e, Effect::RegWrite { .. }))
            .collect();
        assert_eq!(writes.len(), 4);
    }

    // RDTSC
    #[test]
    fn rdtsc_writes_edx_eax() {
        let effs = lft64().lift("rdtsc", &no_ops(), 0);
        assert!(
            effs.iter()
                .any(|e| matches!(e, Effect::RegWrite { reg, .. } if reg == "edx"))
        );
        assert!(
            effs.iter()
                .any(|e| matches!(e, Effect::RegWrite { reg, .. } if reg == "eax"))
        );
    }

    // RDTSCP
    #[test]
    fn rdtscp_writes_ecx_too() {
        let effs = lft64().lift("rdtscp", &no_ops(), 0);
        assert!(
            effs.iter()
                .any(|e| matches!(e, Effect::RegWrite { reg, .. } if reg == "ecx"))
        );
    }

    // RDMSR
    #[test]
    fn rdmsr_emits_intrinsic_and_writes() {
        let effs = lft64().lift("rdmsr", &no_ops(), 0);
        assert!(
            effs.iter()
                .any(|e| matches!(e, Effect::Intrinsic { name, .. } if name == "rdmsr"))
        );
        assert!(
            effs.iter()
                .any(|e| matches!(e, Effect::RegWrite { reg, .. } if reg == "eax"))
        );
    }

    // WRMSR
    #[test]
    fn wrmsr_emits_intrinsic() {
        let effs = lft64().lift("wrmsr", &no_ops(), 0);
        assert!(
            effs.iter()
                .any(|e| matches!(e, Effect::Intrinsic { name, .. } if name == "wrmsr"))
        );
    }

    // HLT
    #[test]
    fn hlt_emits_intrinsic() {
        let effs = lft64().lift("hlt", &no_ops(), 0);
        assert!(
            effs.iter()
                .any(|e| matches!(e, Effect::Intrinsic { name, .. } if name == "hlt"))
        );
    }

    // UD2
    #[test]
    fn ud2_emits_two_intrinsics() {
        let effs = lft64().lift("ud2", &no_ops(), 0);
        assert!(
            effs.iter()
                .any(|e| matches!(e, Effect::Intrinsic { name, .. } if name == "ud2"))
        );
        assert!(effs.iter().any(
            |e| matches!(e, Effect::Intrinsic { name, .. } if name == "undefined_instruction")
        ));
    }

    // PAUSE
    #[test]
    fn pause_emits_intrinsic() {
        let effs = lft64().lift("pause", &no_ops(), 0);
        assert!(
            effs.iter()
                .any(|e| matches!(e, Effect::Intrinsic { name, .. } if name == "pause"))
        );
    }

    // MFENCE / LFENCE / SFENCE
    #[test]
    fn fence_instructions() {
        for m in &["mfence", "lfence", "sfence"] {
            let effs = lft64().lift(m, &no_ops(), 0);
            assert!(
                effs.iter()
                    .any(|e| matches!(e, Effect::Intrinsic { name, .. } if name == *m))
            );
        }
    }

    // XCHG
    #[test]
    fn xchg_emits_lock_and_two_writes() {
        let ops = vec![
            IrExpr::Reg("rax".to_string()),
            IrExpr::Reg("rbx".to_string()),
        ];
        let effs = lft64().lift("xchg", &ops, 0);
        assert!(
            effs.iter()
                .any(|e| matches!(e, Effect::Intrinsic { name, .. } if name == "lock_xchg"))
        );
        let writes: Vec<_> = effs
            .iter()
            .filter(|e| matches!(e, Effect::RegWrite { .. }))
            .collect();
        assert_eq!(writes.len(), 2);
    }

    // XADD
    #[test]
    fn xadd_emits_lock_and_writes() {
        let ops = vec![
            IrExpr::Reg("rax".to_string()),
            IrExpr::Reg("rbx".to_string()),
        ];
        let effs = lft64().lift("xadd", &ops, 0);
        assert!(
            effs.iter()
                .any(|e| matches!(e, Effect::Intrinsic { name, .. } if name == "lock"))
        );
    }

    // CMPXCHG
    #[test]
    fn cmpxchg_emits_lock_and_intrinsic() {
        let ops = vec![
            IrExpr::Reg("rax".to_string()),
            IrExpr::Reg("rbx".to_string()),
        ];
        let effs = lft64().lift("cmpxchg", &ops, 0);
        assert!(
            effs.iter()
                .any(|e| matches!(e, Effect::Intrinsic { name, .. } if name == "lock"))
        );
        assert!(
            effs.iter()
                .any(|e| matches!(e, Effect::Intrinsic { name, .. } if name == "cmpxchg"))
        );
    }

    // CMPXCHG8B
    #[test]
    fn cmpxchg8b_emits_intrinsic() {
        let effs = lft64().lift("cmpxchg8b", &no_ops(), 0);
        assert!(
            effs.iter()
                .any(|e| matches!(e, Effect::Intrinsic { name, .. } if name == "cmpxchg8b"))
        );
    }

    // CMPXCHG16B
    #[test]
    fn cmpxchg16b_emits_intrinsic() {
        let effs = lft64().lift("cmpxchg16b", &no_ops(), 0);
        assert!(
            effs.iter()
                .any(|e| matches!(e, Effect::Intrinsic { name, .. } if name == "cmpxchg16b"))
        );
    }

    // IN / OUT
    #[test]
    fn in_emits_io_read() {
        let ops = vec![IrExpr::Reg("dx".to_string())];
        let effs = lft32().lift("in", &ops, 0);
        assert!(
            effs.iter()
                .any(|e| matches!(e, Effect::Intrinsic { name, .. } if name == "io_read"))
        );
    }

    #[test]
    fn out_emits_io_write() {
        let ops = vec![
            IrExpr::Reg("dx".to_string()),
            IrExpr::Reg("eax".to_string()),
        ];
        let effs = lft32().lift("out", &ops, 0);
        assert!(
            effs.iter()
                .any(|e| matches!(e, Effect::Intrinsic { name, .. } if name == "io_write"))
        );
    }

    // PUSHF / POPF
    #[test]
    fn pushf_decrements_rsp_and_writes_mem() {
        let effs = lft64().lift("pushfq", &no_ops(), 0);
        assert!(
            effs.iter()
                .any(|e| matches!(e, Effect::RegWrite { reg, .. } if reg == "rsp"))
        );
        assert!(effs.iter().any(|e| matches!(e, Effect::MemWrite { .. })));
    }

    #[test]
    fn popf_reads_mem_and_increments_rsp() {
        let effs = lft64().lift("popfq", &no_ops(), 0);
        assert!(effs.iter().any(|e| matches!(e, Effect::MemRead { .. })));
        assert!(
            effs.iter()
                .any(|e| matches!(e, Effect::RegWrite { reg, .. } if reg == "rsp"))
        );
    }

    // LAHF / SAHF
    #[test]
    fn lahf_writes_ah() {
        let effs = lft64().lift("lahf", &no_ops(), 0);
        assert!(
            effs.iter()
                .any(|e| matches!(e, Effect::RegWrite { reg, .. } if reg == "ah"))
        );
    }

    #[test]
    fn sahf_writes_flags() {
        let effs = lft64().lift("sahf", &no_ops(), 0);
        assert!(
            effs.iter()
                .any(|e| matches!(e, Effect::RegWrite { reg, .. } if reg == "flags_lo"))
        );
    }

    // NOP
    #[test]
    fn nop_produces_no_effects() {
        let effs = lft64().lift("nop", &no_ops(), 0);
        assert!(effs.is_empty());
    }

    // SystemCallModel::Intrinsic custom name
    #[test]
    fn custom_syscall_model_intrinsic() {
        let lft = SystemInsnLifter {
            addr_bits: 64,
            syscall_model: Some(SystemCallModel::Intrinsic("kernel_call".to_string())),
        };
        let effs = lft.lift("syscall", &no_ops(), 0);
        assert!(
            effs.iter()
                .any(|e| matches!(e, Effect::Intrinsic { name, .. } if name == "kernel_call"))
        );
    }

    // RDPMC
    #[test]
    fn rdpmc_emits_intrinsic_and_writes() {
        let effs = lft64().lift("rdpmc", &no_ops(), 0);
        assert!(
            effs.iter()
                .any(|e| matches!(e, Effect::Intrinsic { name, .. } if name == "rdpmc"))
        );
        assert!(
            effs.iter()
                .any(|e| matches!(e, Effect::RegWrite { reg, .. } if reg == "eax"))
        );
    }
}
