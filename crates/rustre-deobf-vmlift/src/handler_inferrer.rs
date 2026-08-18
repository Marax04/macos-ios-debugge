//! Handler semantic inference via lightweight symbolic execution.
//!
//! Each VM handler is a small code fragment that implements one guest
//! instruction.  [`HandlerSemanticInferrer`] executes each handler
//! symbolically and classifies its observable effects into a [`HandlerClass`].

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ─────────────────────────────────────────────────────────────────────────────
// HandlerClass — 20+ semantic categories
// ─────────────────────────────────────────────────────────────────────────────

/// High-level semantic category of a VM handler.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum HandlerClass {
    // ── Arithmetic ────────────────────────────────────────────────────────────
    /// `dst ← src0 + src1`
    Add,
    /// `dst ← src0 - src1`
    Sub,
    /// `dst ← src0 * src1`
    Mul,
    /// `dst ← src0 / src1`
    Div,
    /// `dst ← src0 % src1`
    Mod,
    /// `dst ← src0 + 1`
    Inc,
    /// `dst ← src0 - 1`
    Dec,
    /// `dst ← -src0`
    Neg,
    // ── Bitwise ───────────────────────────────────────────────────────────────
    /// `dst ← src0 & src1`
    And,
    /// `dst ← src0 | src1`
    Or,
    /// `dst ← src0 ^ src1`
    Xor,
    /// `dst ← ~src0`
    Not,
    /// `dst ← src0 << src1`
    Shl,
    /// `dst ← src0 >> src1` (logical)
    Shr,
    /// `dst ← src0 >> src1` (arithmetic)
    Sar,
    /// `dst ← rol(src0, src1)`
    Rol,
    /// `dst ← ror(src0, src1)`
    Ror,
    // ── Data movement ─────────────────────────────────────────────────────────
    /// `stack[--sp] ← src`
    Push,
    /// `dst ← stack[sp++]`
    Pop,
    /// `dst ← src` (register or immediate)
    Mov,
    /// `dst ← mem[addr]`
    Load,
    /// `mem[addr] ← src`
    Store,
    // ── Control flow ──────────────────────────────────────────────────────────
    /// Unconditional branch.
    Jump,
    /// Branch if zero / equal.
    JmpIfZero,
    /// Branch if not zero / not equal.
    JmpIfNotZero,
    /// Branch if less than.
    JmpIfLess,
    /// Branch if greater than.
    JmpIfGreater,
    /// Call a subroutine (push return address + branch).
    Call,
    /// Return from subroutine (pop return address + branch).
    Ret,
    // ── Comparison ────────────────────────────────────────────────────────────
    /// Compare two values and write flags.
    Cmp,
    // ── Stack frame ───────────────────────────────────────────────────────────
    /// Enter a new stack frame.
    Enter,
    /// Leave the current stack frame.
    Leave,
    // ── I/O and system ────────────────────────────────────────────────────────
    /// Read from I/O port.
    In,
    /// Write to I/O port.
    Out,
    /// System call / interrupt.
    Syscall,
    /// Halt / terminate execution.
    Halt,
    // ── Crypto / obfuscation helpers ─────────────────────────────────────────
    /// Decrypt or decrypt an operand.
    Decrypt,
    // ── Unclassified ─────────────────────────────────────────────────────────
    /// Handler semantics could not be determined.
    Unknown,
}

impl std::fmt::Display for HandlerClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// HandlerSemantic
// ─────────────────────────────────────────────────────────────────────────────

/// Full semantic description of one VM handler.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandlerSemantic {
    /// Byte offset of the handler in the binary.
    pub offset: usize,
    /// Size of the handler in bytes.
    pub size: usize,
    /// Inferred semantic class.
    pub class: HandlerClass,
    /// Confidence in the classification (0–100).
    pub confidence: u8,
    /// Number of virtual operands consumed.
    pub input_count: u8,
    /// Number of virtual operands produced.
    pub output_count: u8,
    /// Whether this handler reads from memory.
    pub reads_memory: bool,
    /// Whether this handler writes to memory.
    pub writes_memory: bool,
    /// Whether this handler modifies the virtual instruction pointer.
    pub modifies_vip: bool,
    /// Whether this handler modifies the virtual stack pointer.
    pub modifies_vsp: bool,
    /// Human-readable pseudo-code summary.
    pub pseudo_code: String,
    /// Raw byte trace used for classification.
    pub byte_summary: Vec<u8>,
}

impl HandlerSemantic {
    /// Return `true` if this handler is a control-flow transfer.
    #[must_use]
    pub const fn is_branch(&self) -> bool {
        matches!(
            self.class,
            HandlerClass::Jump
                | HandlerClass::JmpIfZero
                | HandlerClass::JmpIfNotZero
                | HandlerClass::JmpIfLess
                | HandlerClass::JmpIfGreater
                | HandlerClass::Call
                | HandlerClass::Ret
        )
    }

    /// Return `true` if this handler terminates execution.
    #[must_use]
    pub const fn is_terminal(&self) -> bool {
        matches!(self.class, HandlerClass::Halt)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Symbolic state
// ─────────────────────────────────────────────────────────────────────────────

/// Symbolic register state for a single-pass execution trace.
#[derive(Debug, Clone, Default)]
struct SymbolicState {
    /// Symbolic values in each x86 register (by index 0=eax, 1=ecx, …).
    regs: HashMap<u8, SymbolicValue>,
    /// Observed memory reads.
    mem_reads: usize,
    /// Observed memory writes.
    mem_writes: usize,
    /// Observed stack pushes.
    stack_pushes: usize,
    /// Observed stack pops.
    stack_pops: usize,
    /// Whether a branch was observed.
    branch_seen: bool,
    /// Whether a return was observed.
    ret_seen: bool,
    /// Whether a call was observed.
    call_seen: bool,
    /// The primary arithmetic operation observed.
    primary_op: Option<ArithOp>,
}

/// Symbolic value in a register.
#[derive(Debug, Clone)]
enum SymbolicValue {
    Concrete,
}

/// Simplified arithmetic operation category.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ArithOp {
    Add,
    Sub,
    Mul,
    Div,
    And,
    Or,
    Xor,
    Not,
    Shl,
    Shr,
    Sar,
    Rol,
    Ror,
    Neg,
    Cmp,
}

// ─────────────────────────────────────────────────────────────────────────────
// HandlerSemanticInferrer
// ─────────────────────────────────────────────────────────────────────────────

/// Infers the semantics of VM handlers via symbolic x86 execution.
///
/// Each handler is typically 10–100 bytes long.  The inferrer executes it
/// symbolically using a minimal interpreter that tracks arithmetic operations,
/// memory accesses, and control-flow changes.
///
/// ```rust
/// use rustre_deobf_vmlift::handler_inferrer::HandlerSemanticInferrer;
///
/// let inferrer = HandlerSemanticInferrer::new();
/// // push eax; add eax, ecx; pop ecx
/// let handler_bytes = [0x50u8, 0x01, 0xC8, 0x59];
/// let sem = inferrer.infer(0x1000, &handler_bytes);
/// println!("Handler class: {}", sem.class);
/// ```
#[derive(Debug, Default)]
pub struct HandlerSemanticInferrer {
    max_insn: usize,
}

impl HandlerSemanticInferrer {
    /// Create a new inferrer.
    #[must_use]
    pub const fn new() -> Self {
        Self { max_insn: 64 }
    }

    /// Set the maximum number of instructions to trace per handler.
    #[must_use]
    pub const fn with_max_insn(mut self, n: usize) -> Self {
        self.max_insn = n;
        self
    }

    /// Infer the semantics of a single handler.
    #[must_use]
    pub fn infer(&self, offset: usize, handler: &[u8]) -> HandlerSemantic {
        let state = self.symbolic_exec(handler);
        let class = self.classify(&state, handler);
        let confidence = self.confidence_for(&class, &state, handler);
        let pseudo_code = self.pseudo_code_for(&class, &state);

        HandlerSemantic {
            offset,
            size: handler.len(),
            class,
            confidence,
            input_count: (state.stack_pops + if state.mem_reads > 0 { 1 } else { 0 }) as u8,
            output_count: (state.stack_pushes + if state.mem_writes > 0 { 1 } else { 0 }) as u8,
            reads_memory: state.mem_reads > 0,
            writes_memory: state.mem_writes > 0,
            modifies_vip: state.branch_seen || state.ret_seen,
            modifies_vsp: state.stack_pushes > 0 || state.stack_pops > 0,
            pseudo_code,
            byte_summary: handler.iter().take(16).copied().collect(),
        }
    }

    /// Infer semantics for a list of handlers at known offsets.
    #[must_use]
    pub fn infer_all(&self, handlers: &[(usize, Vec<u8>)]) -> Vec<HandlerSemantic> {
        handlers
            .iter()
            .map(|(offset, bytes)| self.infer(*offset, bytes))
            .collect()
    }

    fn symbolic_exec(&self, handler: &[u8]) -> SymbolicState {
        let mut state = SymbolicState::default();
        let mut pc = 0usize;
        let mut insn_count = 0;

        while pc < handler.len() && insn_count < self.max_insn {
            let b = handler[pc];
            match b {
                // ── Stack ────────────────────────────────────────────────────
                0x50..=0x57 => {
                    state.stack_pushes += 1;
                    pc += 1;
                } // PUSH reg
                0x58..=0x5F => {
                    state.stack_pops += 1;
                    pc += 1;
                } // POP  reg
                0x68 => {
                    state.stack_pushes += 1;
                    pc += 5;
                } // PUSH imm32
                0x6A => {
                    state.stack_pushes += 1;
                    pc += 2;
                } // PUSH imm8

                // ── Arithmetic (reg/mem, /r) ──────────────────────────────────
                0x01 | 0x03 => {
                    state.primary_op = Some(ArithOp::Add);
                    pc += 2;
                }
                0x29 | 0x2B => {
                    state.primary_op = Some(ArithOp::Sub);
                    pc += 2;
                }
                0x21 | 0x23 => {
                    state.primary_op = Some(ArithOp::And);
                    pc += 2;
                }
                0x09 | 0x0B => {
                    state.primary_op = Some(ArithOp::Or);
                    pc += 2;
                }
                0x31 | 0x33 => {
                    state.primary_op = Some(ArithOp::Xor);
                    pc += 2;
                }
                0x0F if pc + 1 < handler.len() => match handler[pc + 1] {
                    0xAF => {
                        state.primary_op = Some(ArithOp::Mul);
                        pc += 3;
                    }
                    0xA4 | 0xA5 => {
                        state.primary_op = Some(ArithOp::Shl);
                        pc += 4;
                    }
                    0xAC | 0xAD => {
                        state.primary_op = Some(ArithOp::Shr);
                        pc += 4;
                    }
                    0xBC | 0xBD => {
                        state.primary_op = Some(ArithOp::Cmp);
                        pc += 3;
                    }
                    _ => {
                        pc += 2;
                    }
                },
                0xD0..=0xD3 if pc + 1 < handler.len() => {
                    // Shift/rotate group: /4=shl /5=shr /6=sal /7=sar /0=rol /1=ror
                    let reg = (handler[pc + 1] >> 3) & 7;
                    state.primary_op = Some(match reg {
                        0 => ArithOp::Rol,
                        1 => ArithOp::Ror,
                        4 | 6 => ArithOp::Shl,
                        5 => ArithOp::Shr,
                        7 => ArithOp::Sar,
                        _ => ArithOp::Shl,
                    });
                    pc += 2;
                }
                0xF6 | 0xF7 if pc + 1 < handler.len() => {
                    let reg = (handler[pc + 1] >> 3) & 7;
                    state.primary_op = Some(match reg {
                        2 => ArithOp::Not,
                        3 => ArithOp::Neg,
                        4 => ArithOp::Mul,
                        6 => ArithOp::Div,
                        _ => ArithOp::Mul,
                    });
                    pc += 2;
                }

                // ── CMP ───────────────────────────────────────────────────────
                0x39 | 0x3B | 0x83 if pc + 1 < handler.len() && (handler[pc + 1] >> 3) & 7 == 7 => {
                    state.primary_op = Some(ArithOp::Cmp);
                    pc += if b == 0x83 { 3 } else { 2 };
                }
                0x38 | 0x3A => {
                    state.primary_op = Some(ArithOp::Cmp);
                    pc += 2;
                }

                // ── Memory access ─────────────────────────────────────────────
                0x8A | 0x8B => {
                    state.mem_reads += 1;
                    pc += 2;
                } // MOV r, m
                0x88 | 0x89 => {
                    state.mem_writes += 1;
                    pc += 2;
                } // MOV m, r
                0xA4 | 0xA5 => {
                    state.mem_reads += 1;
                    state.mem_writes += 1;
                    pc += 1;
                } // MOVS
                0xA0 | 0xA1 => {
                    state.mem_reads += 1;
                    pc += if b == 0xA0 { 2 } else { 5 };
                }
                0xA2 | 0xA3 => {
                    state.mem_writes += 1;
                    pc += if b == 0xA2 { 2 } else { 5 };
                }
                // LODS* / STOS*
                0xAC | 0xAD => {
                    state.mem_reads += 1;
                    pc += 1;
                }
                0xAA | 0xAB => {
                    state.mem_writes += 1;
                    pc += 1;
                }

                // ── Control flow ──────────────────────────────────────────────
                0xE8 => {
                    state.call_seen = true;
                    pc += 5;
                }
                0xE9 => {
                    state.branch_seen = true;
                    pc += 5;
                }
                0xEB => {
                    state.branch_seen = true;
                    pc += 2;
                }
                0x74 | 0x75 | 0x7C | 0x7D | 0x7E | 0x7F | 0x72 | 0x73 | 0x76 | 0x77 | 0x78
                | 0x79 => {
                    state.branch_seen = true;
                    pc += 2;
                }
                0xC3 | 0xCB | 0xC2 | 0xCA => {
                    state.ret_seen = true;
                    break;
                }
                0xFF if pc + 1 < handler.len() => {
                    let modrm = handler[pc + 1];
                    let reg = (modrm >> 3) & 7;
                    match reg {
                        2 => state.call_seen = true,
                        4 => state.branch_seen = true,
                        _ => {}
                    }
                    pc += 2;
                }

                // ── MOV imm ───────────────────────────────────────────────────
                0xB8..=0xBF => {
                    state.regs.insert(b - 0xB8, SymbolicValue::Concrete);
                    pc += 5;
                }
                0xB0..=0xB7 => {
                    state.regs.insert(b - 0xB0, SymbolicValue::Concrete);
                    pc += 2;
                }

                // ── NOP / prefixes ────────────────────────────────────────────
                0x90 | 0x66 | 0x67 | 0xF2 | 0xF3 => {
                    pc += 1;
                }

                // ── REX prefix (x64) ─────────────────────────────────────────
                0x40..=0x4F => {
                    pc += 1;
                } // skip REX

                // ── Halt (custom VM) ──────────────────────────────────────────
                0xF4 => {
                    break;
                } // HLT

                _ => {
                    pc += 1;
                }
            }
            insn_count += 1;
        }

        state
    }

    fn classify(&self, state: &SymbolicState, handler: &[u8]) -> HandlerClass {
        // A handler is a pure `Ret` only when returning is its *sole* observable
        // effect.  Nearly every VM handler ends with a `ret` back to the
        // dispatcher, so `ret_seen` alone must not preempt the real operation
        // (arithmetic, memory access, stack push/pop, etc.).
        if state.ret_seen
            && !state.branch_seen
            && !state.call_seen
            && state.stack_pops == 0
            && state.stack_pushes == 0
            && state.mem_reads == 0
            && state.mem_writes == 0
            && state.primary_op.is_none()
        {
            return HandlerClass::Ret;
        }
        if state.call_seen {
            return HandlerClass::Call;
        }
        if state.branch_seen {
            if let Some(op) = &state.primary_op
                && *op == ArithOp::Cmp {
                    return HandlerClass::JmpIfZero;
                }
            return HandlerClass::Jump;
        }
        if handler.contains(&0xF4) {
            return HandlerClass::Halt;
        }

        if state.stack_pushes > 0 && state.mem_reads == 0 && state.stack_pops == 0 {
            return HandlerClass::Push;
        }
        if state.stack_pops > 0 && state.mem_reads == 0 && state.stack_pushes == 0 {
            return HandlerClass::Pop;
        }
        if state.mem_reads > 0 && state.mem_writes == 0 {
            return HandlerClass::Load;
        }
        if state.mem_writes > 0 && state.mem_reads == 0 {
            return HandlerClass::Store;
        }

        match &state.primary_op {
            Some(ArithOp::Add) => HandlerClass::Add,
            Some(ArithOp::Sub) => HandlerClass::Sub,
            Some(ArithOp::Mul) => HandlerClass::Mul,
            Some(ArithOp::Div) => HandlerClass::Div,
            Some(ArithOp::And) => HandlerClass::And,
            Some(ArithOp::Or) => HandlerClass::Or,
            Some(ArithOp::Xor) => {
                // XOR with self → zero move; XOR with key → decrypt
                if is_xor_zero(handler) {
                    HandlerClass::Mov
                } else {
                    HandlerClass::Xor
                }
            }
            Some(ArithOp::Not) => HandlerClass::Not,
            Some(ArithOp::Neg) => HandlerClass::Neg,
            Some(ArithOp::Shl) => HandlerClass::Shl,
            Some(ArithOp::Shr) => HandlerClass::Shr,
            Some(ArithOp::Sar) => HandlerClass::Sar,
            Some(ArithOp::Rol) => HandlerClass::Rol,
            Some(ArithOp::Ror) => HandlerClass::Ror,
            Some(ArithOp::Cmp) => HandlerClass::Cmp,
            None => {
                // Check for INC/DEC
                if handler.iter().any(|&b| matches!(b, 0x40..=0x47)) {
                    return HandlerClass::Inc;
                }
                if handler.iter().any(|&b| matches!(b, 0x48..=0x4F)) {
                    return HandlerClass::Dec;
                }
                // MOV-only
                if state.mem_reads == 0 && state.mem_writes == 0 {
                    return HandlerClass::Mov;
                }
                HandlerClass::Unknown
            }
        }
    }

    fn confidence_for(&self, class: &HandlerClass, state: &SymbolicState, handler: &[u8]) -> u8 {
        let base: u8 = match class {
            HandlerClass::Unknown => 10,
            HandlerClass::Halt | HandlerClass::Ret | HandlerClass::Call => 85,
            HandlerClass::Push | HandlerClass::Pop => 80,
            HandlerClass::Load | HandlerClass::Store => 75,
            HandlerClass::Jump | HandlerClass::JmpIfZero => 78,
            HandlerClass::Add | HandlerClass::Sub | HandlerClass::Xor => 82,
            _ => 65,
        };

        // Penalise if no primary op was found for arithmetic classes
        let penalty = if state.primary_op.is_none()
            && matches!(class, HandlerClass::Add | HandlerClass::Sub)
        {
            20u8
        } else {
            0
        };
        // Bonus for short handlers (less noise)
        let bonus = if handler.len() < 20 { 5u8 } else { 0 };
        base.saturating_sub(penalty).saturating_add(bonus).min(100)
    }

    fn pseudo_code_for(&self, class: &HandlerClass, state: &SymbolicState) -> String {
        match class {
            HandlerClass::Push => format!(
                "push vr; sp -= {}",
                if state.stack_pushes > 0 { "4" } else { "?" }
            ),
            HandlerClass::Pop => "dst = [vsp]; vsp += 4".to_owned(),
            HandlerClass::Load => "dst = mem[addr]".to_owned(),
            HandlerClass::Store => "mem[addr] = src".to_owned(),
            HandlerClass::Add => "dst = src0 + src1".to_owned(),
            HandlerClass::Sub => "dst = src0 - src1".to_owned(),
            HandlerClass::Mul => "dst = src0 * src1".to_owned(),
            HandlerClass::Div => "dst = src0 / src1".to_owned(),
            HandlerClass::And => "dst = src0 & src1".to_owned(),
            HandlerClass::Or => "dst = src0 | src1".to_owned(),
            HandlerClass::Xor => "dst = src0 ^ src1".to_owned(),
            HandlerClass::Not => "dst = ~src0".to_owned(),
            HandlerClass::Neg => "dst = -src0".to_owned(),
            HandlerClass::Shl => "dst = src0 << src1".to_owned(),
            HandlerClass::Shr => "dst = src0 >> src1".to_owned(),
            HandlerClass::Sar => "dst = src0 >>> src1".to_owned(),
            HandlerClass::Rol => "dst = rol(src0, src1)".to_owned(),
            HandlerClass::Ror => "dst = ror(src0, src1)".to_owned(),
            HandlerClass::Cmp => "flags = cmp(src0, src1)".to_owned(),
            HandlerClass::Jump => "vip = target".to_owned(),
            HandlerClass::JmpIfZero => "if (flags.ZF) vip = target".to_owned(),
            HandlerClass::JmpIfNotZero => "if (!flags.ZF) vip = target".to_owned(),
            HandlerClass::JmpIfLess => "if (flags.SF != flags.OF) vip = target".to_owned(),
            HandlerClass::JmpIfGreater => {
                "if (!flags.ZF && flags.SF == flags.OF) vip = target".to_owned()
            }
            HandlerClass::Call => "push retaddr; vip = target".to_owned(),
            HandlerClass::Ret => "vip = pop()".to_owned(),
            HandlerClass::Halt => "halt()".to_owned(),
            HandlerClass::Mov => "dst = src".to_owned(),
            HandlerClass::Inc => "dst = src + 1".to_owned(),
            HandlerClass::Dec => "dst = src - 1".to_owned(),
            HandlerClass::Mod => "dst = src0 % src1".to_owned(),
            HandlerClass::In => "dst = in(port)".to_owned(),
            HandlerClass::Out => "out(port, src)".to_owned(),
            HandlerClass::Syscall => "syscall(n, ...)".to_owned(),
            HandlerClass::Decrypt => "dst = decrypt(src)".to_owned(),
            HandlerClass::Enter => "push rbp; rbp = rsp".to_owned(),
            HandlerClass::Leave => "rsp = rbp; pop rbp".to_owned(),
            HandlerClass::Unknown => "???".to_owned(),
        }
    }
}

/// Check if a byte pattern is `xor reg, reg` (self-XOR → zeroing move).
fn is_xor_zero(handler: &[u8]) -> bool {
    handler.windows(2).any(|w| {
        // XOR r, r: 31 /r where r == source == dest (Mod=11, reg=rm)
        w[0] == 0x31 || w[0] == 0x33
    }) && handler.windows(2).any(|w| {
        // The ModRM byte has reg == rm (e.g. 0xC0=xor eax,eax, 0xC9=xor ecx,ecx …)
        w[0] == 0x31 && ((w[1] & 0x38) >> 3 == (w[1] & 0x07))
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn inf() -> HandlerSemanticInferrer {
        HandlerSemanticInferrer::new()
    }

    #[test]
    fn test_infer_push() {
        // push eax (50) + ret (C3)
        let handler = [0x50u8, 0xC3];
        let sem = inf().infer(0, &handler);
        assert_eq!(sem.class, HandlerClass::Push);
        assert!(sem.modifies_vsp);
    }

    #[test]
    fn test_infer_pop() {
        // pop eax (58) + ret (C3)
        let handler = [0x58u8, 0xC3];
        let sem = inf().infer(0, &handler);
        assert_eq!(sem.class, HandlerClass::Pop);
    }

    #[test]
    fn test_infer_add() {
        // add eax, ecx (01 C8) + ret (C3)
        let handler = [0x01u8, 0xC8, 0xC3];
        let sem = inf().infer(0, &handler);
        assert_eq!(sem.class, HandlerClass::Add);
    }

    #[test]
    fn test_infer_xor() {
        // xor eax, ecx (31 C8) + ret (C3)
        let handler = [0x31u8, 0xC8, 0xC3];
        let sem = inf().infer(0, &handler);
        assert_eq!(sem.class, HandlerClass::Xor);
    }

    #[test]
    fn test_infer_xor_zero() {
        // xor eax, eax (31 C0) + ret (C3)
        let handler = [0x31u8, 0xC0, 0xC3];
        let sem = inf().infer(0, &handler);
        // xor eax, eax is a zeroing move
        assert!(matches!(sem.class, HandlerClass::Mov | HandlerClass::Xor));
    }

    #[test]
    fn test_infer_ret() {
        let handler = [0xC3u8];
        let sem = inf().infer(0, &handler);
        assert_eq!(sem.class, HandlerClass::Ret);
        assert!(sem.modifies_vip);
    }

    #[test]
    fn test_infer_jump() {
        // jmp short +0 (EB 00) + ret
        let handler = [0xEBu8, 0x00, 0xC3];
        let sem = inf().infer(0, &handler);
        assert_eq!(sem.class, HandlerClass::Jump);
    }

    #[test]
    fn test_infer_load() {
        // mov eax, [eax] (8B 00) + ret
        let handler = [0x8Bu8, 0x00, 0xC3];
        let sem = inf().infer(0, &handler);
        assert_eq!(sem.class, HandlerClass::Load);
        assert!(sem.reads_memory);
    }

    #[test]
    fn test_infer_store() {
        // mov [eax], ecx (89 08) + ret
        let handler = [0x89u8, 0x08, 0xC3];
        let sem = inf().infer(0, &handler);
        assert_eq!(sem.class, HandlerClass::Store);
        assert!(sem.writes_memory);
    }

    #[test]
    fn test_infer_halt() {
        let handler = [0xF4u8, 0xC3]; // HLT + RET
        let sem = inf().infer(0, &handler);
        assert_eq!(sem.class, HandlerClass::Halt);
    }

    #[test]
    fn test_infer_all() {
        let handlers = vec![
            (0x1000, vec![0x50u8, 0xC3]),
            (0x1010, vec![0x58u8, 0xC3]),
            (0x1020, vec![0xC3u8]),
        ];
        let results = inf().infer_all(&handlers);
        assert_eq!(results.len(), 3);
    }

    #[test]
    fn test_handler_is_branch() {
        let sem = HandlerSemantic {
            offset: 0,
            size: 2,
            class: HandlerClass::Jump,
            confidence: 80,
            input_count: 0,
            output_count: 0,
            reads_memory: false,
            writes_memory: false,
            modifies_vip: true,
            modifies_vsp: false,
            pseudo_code: "vip = target".to_owned(),
            byte_summary: vec![],
        };
        assert!(sem.is_branch());
    }

    #[test]
    fn test_handler_class_display() {
        assert_eq!(HandlerClass::Add.to_string(), "Add");
        assert_eq!(HandlerClass::Unknown.to_string(), "Unknown");
    }

    #[test]
    fn test_pseudo_code_produced() {
        let handler = [0x01u8, 0xC8, 0xC3]; // add eax, ecx + ret
        let sem = inf().infer(0, &handler);
        assert!(!sem.pseudo_code.is_empty());
    }
}
