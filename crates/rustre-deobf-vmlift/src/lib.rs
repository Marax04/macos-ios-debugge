//! `rustre-deobf-vmlift`
//!
//! This crate is part of the `RustRE` Suite, a premium reverse engineering platform.
//!
//! # Deobfuscation Pass: VMLIFT
//! Performs lifting of VM bytecode to an intermediate representation (IR) for static analysis.

pub mod bytecode_finder;
pub mod custom_vm_identifier;
pub mod dispatcher_detector;
pub mod handler_inferrer;
pub mod handler_semantic_db;
pub mod isa_synthesizer;
pub mod lifted_ir_optimizer;
pub mod lifter_to_llil;
pub mod protector_patterns;
pub mod tigress_lifter;
pub mod virtualized_function;
pub mod vm_isa_recovery;
pub mod vm_protection_analysis;
pub mod vm_handler_analyzer;
pub mod vm_bytecode_lifter;
pub mod vm_dispatcher_finder;
pub mod vm_isa_complete;

// Ensure dependencies are registered to prevent unused-dependency warnings.
use rustre_core as _;
use rustre_deobf_vm as _;

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use dispatcher_detector::VmDispatcher;

/// Supported Guest VM opcodes for intermediate representation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GuestOpcode {
    /// Add source register to destination register.
    Add,
    /// Subtract source register from destination register.
    Sub,
    /// Push a register or immediate onto the stack.
    Push,
    /// Pop from stack into a destination register.
    Pop,
    /// Load from memory or immediate value into a register.
    Load,
    /// Store a register value to memory.
    Store,
    /// Halt execution.
    Halt,
}

/// A decoded guest instruction representing the lifted intermediate state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestInstruction {
    /// The guest opcode.
    pub opcode: GuestOpcode,
    /// Optional destination register.
    pub reg_dst: Option<usize>,
    /// Optional source register.
    pub reg_src: Option<usize>,
    /// Optional 32-bit immediate value.
    pub imm: Option<u32>,
}

impl std::fmt::Display for GuestInstruction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.opcode {
            GuestOpcode::Add => {
                let dst = self.reg_dst.map_or("?".to_string(), |r| format!("r{r}"));
                let src = self.reg_src.map_or("?".to_string(), |r| format!("r{r}"));
                write!(f, "ADD {dst}, {src}")
            }
            GuestOpcode::Sub => {
                let dst = self.reg_dst.map_or("?".to_string(), |r| format!("r{r}"));
                let src = self.reg_src.map_or("?".to_string(), |r| format!("r{r}"));
                write!(f, "SUB {dst}, {src}")
            }
            GuestOpcode::Push => {
                if let Some(src) = self.reg_src {
                    write!(f, "PUSH r{src}")
                } else if let Some(imm) = self.imm {
                    write!(f, "PUSH {imm:#x}")
                } else {
                    write!(f, "PUSH ?")
                }
            }
            GuestOpcode::Pop => {
                let dst = self.reg_dst.map_or("?".to_string(), |r| format!("r{r}"));
                write!(f, "POP {dst}")
            }
            GuestOpcode::Load => {
                let dst = self.reg_dst.map_or("?".to_string(), |r| format!("r{r}"));
                match (self.reg_src, self.imm) {
                    (Some(src), Some(imm)) => {
                        if imm == 0 {
                            write!(f, "LOAD {dst}, [r{src}]")
                        } else {
                            write!(f, "LOAD {dst}, [r{src} + {imm:#x}]")
                        }
                    }
                    (Some(src), None) => write!(f, "LOAD {dst}, [r{src}]"),
                    (None, Some(imm)) => write!(f, "LOAD {dst}, {imm:#x}"),
                    (None, None) => write!(f, "LOAD {dst}, ?"),
                }
            }
            GuestOpcode::Store => {
                let src = self.reg_src.map_or("?".to_string(), |r| format!("r{r}"));
                match (self.reg_dst, self.imm) {
                    (Some(dst), Some(imm)) => {
                        if imm == 0 {
                            write!(f, "STORE [r{dst}], {src}")
                        } else {
                            write!(f, "STORE [r{dst} + {imm:#x}], {src}")
                        }
                    }
                    (Some(dst), None) => write!(f, "STORE [r{dst}], {src}"),
                    (None, Some(imm)) => write!(f, "STORE [{imm:#x}], {src}"),
                    (None, None) => write!(f, "STORE [?], {src}"),
                }
            }
            GuestOpcode::Halt => write!(f, "HALT"),
        }
    }
}

/// Lifter module to decode bytecode buffers into guest instructions.
pub struct VmLifter;

impl VmLifter {
    /// Decodes a bytecode buffer into a list of `GuestInstruction` structures.
    ///
    /// # Bytecode Encoding Scheme:
    /// - `0x01` (Add): `0x01` + `reg_dst: u8` + `reg_src: u8`
    /// - `0x02` (Sub): `0x02` + `reg_dst: u8` + `reg_src: u8`
    /// - `0x03` (Push register): `0x03` + `reg_src: u8`
    /// - `0x04` (Pop register): `0x04` + `reg_dst: u8`
    /// - `0x05` (Load from memory): `0x05` + `reg_dst: u8` + `reg_src: u8` + `imm: u32` (little-endian)
    /// - `0x06` (Store to memory): `0x06` + `reg_dst: u8` (base address) + `reg_src: u8` (val) + `imm: u32` (offset, little-endian)
    /// - `0x07` (Halt): `0x07`
    /// - `0x08` (Load immediate): `0x08` + `reg_dst: u8` + `imm: u32` (little-endian)
    /// - `0x09` (Push immediate): `0x09` + `imm: u32` (little-endian)
    pub fn lift_to_instructions(bytecode: &[u8]) -> Result<Vec<GuestInstruction>, &'static str> {
        let mut instrs = Vec::new();
        let mut pc = 0;
        while pc < bytecode.len() {
            let opcode_byte = bytecode[pc];
            pc += 1;
            match opcode_byte {
                0x01 => {
                    if pc + 2 > bytecode.len() {
                        return Err("Unexpected end of bytecode for Add instruction");
                    }
                    let reg_dst = bytecode[pc] as usize;
                    let reg_src = bytecode[pc + 1] as usize;
                    pc += 2;
                    instrs.push(GuestInstruction {
                        opcode: GuestOpcode::Add,
                        reg_dst: Some(reg_dst),
                        reg_src: Some(reg_src),
                        imm: None,
                    });
                }
                0x02 => {
                    if pc + 2 > bytecode.len() {
                        return Err("Unexpected end of bytecode for Sub instruction");
                    }
                    let reg_dst = bytecode[pc] as usize;
                    let reg_src = bytecode[pc + 1] as usize;
                    pc += 2;
                    instrs.push(GuestInstruction {
                        opcode: GuestOpcode::Sub,
                        reg_dst: Some(reg_dst),
                        reg_src: Some(reg_src),
                        imm: None,
                    });
                }
                0x03 => {
                    if pc + 1 > bytecode.len() {
                        return Err("Unexpected end of bytecode for Push reg instruction");
                    }
                    let reg_src = bytecode[pc] as usize;
                    pc += 1;
                    instrs.push(GuestInstruction {
                        opcode: GuestOpcode::Push,
                        reg_dst: None,
                        reg_src: Some(reg_src),
                        imm: None,
                    });
                }
                0x04 => {
                    if pc + 1 > bytecode.len() {
                        return Err("Unexpected end of bytecode for Pop reg instruction");
                    }
                    let reg_dst = bytecode[pc] as usize;
                    pc += 1;
                    instrs.push(GuestInstruction {
                        opcode: GuestOpcode::Pop,
                        reg_dst: Some(reg_dst),
                        reg_src: None,
                        imm: None,
                    });
                }
                0x05 => {
                    if pc + 6 > bytecode.len() {
                        return Err("Unexpected end of bytecode for Load instruction");
                    }
                    let reg_dst = bytecode[pc] as usize;
                    let reg_src = bytecode[pc + 1] as usize;
                    let imm = u32::from_le_bytes([
                        bytecode[pc + 2],
                        bytecode[pc + 3],
                        bytecode[pc + 4],
                        bytecode[pc + 5],
                    ]);
                    pc += 6;
                    instrs.push(GuestInstruction {
                        opcode: GuestOpcode::Load,
                        reg_dst: Some(reg_dst),
                        reg_src: Some(reg_src),
                        imm: Some(imm),
                    });
                }
                0x06 => {
                    if pc + 6 > bytecode.len() {
                        return Err("Unexpected end of bytecode for Store instruction");
                    }
                    let reg_dst = bytecode[pc] as usize;
                    let reg_src = bytecode[pc + 1] as usize;
                    let imm = u32::from_le_bytes([
                        bytecode[pc + 2],
                        bytecode[pc + 3],
                        bytecode[pc + 4],
                        bytecode[pc + 5],
                    ]);
                    pc += 6;
                    instrs.push(GuestInstruction {
                        opcode: GuestOpcode::Store,
                        reg_dst: Some(reg_dst),
                        reg_src: Some(reg_src),
                        imm: Some(imm),
                    });
                }
                0x07 => {
                    instrs.push(GuestInstruction {
                        opcode: GuestOpcode::Halt,
                        reg_dst: None,
                        reg_src: None,
                        imm: None,
                    });
                }
                0x08 => {
                    if pc + 5 > bytecode.len() {
                        return Err("Unexpected end of bytecode for LoadImm instruction");
                    }
                    let reg_dst = bytecode[pc] as usize;
                    let imm = u32::from_le_bytes([
                        bytecode[pc + 1],
                        bytecode[pc + 2],
                        bytecode[pc + 3],
                        bytecode[pc + 4],
                    ]);
                    pc += 5;
                    instrs.push(GuestInstruction {
                        opcode: GuestOpcode::Load,
                        reg_dst: Some(reg_dst),
                        reg_src: None,
                        imm: Some(imm),
                    });
                }
                0x09 => {
                    if pc + 4 > bytecode.len() {
                        return Err("Unexpected end of bytecode for PushImm instruction");
                    }
                    let imm = u32::from_le_bytes([
                        bytecode[pc],
                        bytecode[pc + 1],
                        bytecode[pc + 2],
                        bytecode[pc + 3],
                    ]);
                    pc += 4;
                    instrs.push(GuestInstruction {
                        opcode: GuestOpcode::Push,
                        reg_dst: None,
                        reg_src: None,
                        imm: Some(imm),
                    });
                }
                _ => return Err("Unknown opcode in bytecode"),
            }
        }
        Ok(instrs)
    }

    /// Lenient variant of [`VmLifter::lift_to_instructions`] that never returns
    /// an error: unknown opcodes are emitted as `"UNK_xx"` one-byte placeholders
    /// and decoding continues.  Suitable for analysing arbitrary bytecode blobs.
    #[must_use]
    pub fn lift_to_instructions_lenient(bytecode: &[u8]) -> Vec<GuestInstruction> {
        // Delegate to the non-strict VmBytecodeLifter which already handles
        // unknown opcodes gracefully, then project into GuestInstruction.
        use vm_bytecode_lifter::{LiftedOp, VmBytecodeLifter, VmBytecode, BinOp};
        let bc = VmBytecode::new(bytecode.to_vec(), 0);
        let lifter = VmBytecodeLifter::new(); // non-strict by default
        let lifted = match lifter.lift(&bc) {
            Ok(v) => v,
            Err(_) => return Vec::new(),
        };
        lifted.into_iter().map(|i| {
            match &i.op {
                LiftedOp::BinOp(BinOp::Add) => GuestInstruction {
                    opcode: GuestOpcode::Add,
                    reg_dst: i.operands.first().and_then(|o| if let vm_bytecode_lifter::LiftedOperand::VirtualReg(r) = o { Some(*r as usize) } else { None }),
                    reg_src: i.operands.get(1).and_then(|o| if let vm_bytecode_lifter::LiftedOperand::VirtualReg(r) = o { Some(*r as usize) } else { None }),
                    imm: None,
                },
                LiftedOp::BinOp(BinOp::Sub) => GuestInstruction {
                    opcode: GuestOpcode::Sub,
                    reg_dst: i.operands.first().and_then(|o| if let vm_bytecode_lifter::LiftedOperand::VirtualReg(r) = o { Some(*r as usize) } else { None }),
                    reg_src: i.operands.get(1).and_then(|o| if let vm_bytecode_lifter::LiftedOperand::VirtualReg(r) = o { Some(*r as usize) } else { None }),
                    imm: None,
                },
                LiftedOp::Push => GuestInstruction {
                    opcode: GuestOpcode::Push,
                    reg_dst: None,
                    reg_src: i.operands.first().and_then(|o| if let vm_bytecode_lifter::LiftedOperand::VirtualReg(r) = o { Some(*r as usize) } else { None }),
                    imm: i.operands.first().and_then(|o| if let vm_bytecode_lifter::LiftedOperand::Immediate(v) = o { Some(*v as u32) } else { None }),
                },
                LiftedOp::Pop => GuestInstruction {
                    opcode: GuestOpcode::Pop,
                    reg_dst: i.operands.first().and_then(|o| if let vm_bytecode_lifter::LiftedOperand::VirtualReg(r) = o { Some(*r as usize) } else { None }),
                    reg_src: None,
                    imm: None,
                },
                LiftedOp::Load { .. } => GuestInstruction {
                    opcode: GuestOpcode::Load,
                    reg_dst: i.operands.first().and_then(|o| if let vm_bytecode_lifter::LiftedOperand::VirtualReg(r) = o { Some(*r as usize) } else { None }),
                    reg_src: i.operands.get(1).and_then(|o| if let vm_bytecode_lifter::LiftedOperand::VirtualReg(r) = o { Some(*r as usize) } else { None }),
                    imm: i.operands.get(1).and_then(|o| if let vm_bytecode_lifter::LiftedOperand::Immediate(v) = o { Some(*v as u32) } else { None }),
                },
                LiftedOp::Store { .. } => GuestInstruction {
                    opcode: GuestOpcode::Store,
                    reg_dst: i.operands.first().and_then(|o| if let vm_bytecode_lifter::LiftedOperand::VirtualReg(r) = o { Some(*r as usize) } else { None }),
                    reg_src: i.operands.get(1).and_then(|o| if let vm_bytecode_lifter::LiftedOperand::VirtualReg(r) = o { Some(*r as usize) } else { None }),
                    imm: None,
                },
                LiftedOp::Halt => GuestInstruction {
                    opcode: GuestOpcode::Halt,
                    reg_dst: None,
                    reg_src: None,
                    imm: None,
                },
                _ => {
                    // Unknown or unhandled opcode: emit a Halt placeholder so the
                    // pseudo-IL stream is never empty and callers can see something.
                    GuestInstruction {
                        opcode: GuestOpcode::Halt,
                        reg_dst: None,
                        reg_src: None,
                        imm: None,
                    }
                }
            }
        }).collect()
    }

    /// Translates guest instructions to readable pseudo-IL strings for static analysis.
    #[must_use]
    pub fn to_pseudo_il(instrs: &[GuestInstruction]) -> Vec<String> {
        instrs.iter().map(std::string::ToString::to_string).collect()
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// VmDispatcherDetector — binary-level dispatcher discovery
// ═════════════════════════════════════════════════════════════════════════════

/// Detected dispatcher pattern kind at the byte-pattern level.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RawDispatcherKind {
    /// Indirect `jmp [reg*8 + table]` — bytes `FF 24 CD ...`.
    IndirectIndexedJmp,
    /// Computed jump `FF E0` (jmp rax) or `FF E1` (jmp rcx) after table load.
    ComputedJmp,
    /// `call + pop + add` chain common in VM stub prologues.
    CallPopAddChain,
}

impl std::fmt::Display for RawDispatcherKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IndirectIndexedJmp => write!(f, "indirect-indexed-jmp [reg*8+table]"),
            Self::ComputedJmp => write!(f, "computed-jmp (FF E0/E1)"),
            Self::CallPopAddChain => write!(f, "call+pop+add VM stub chain"),
        }
    }
}

/// A raw dispatcher site found by byte-pattern scanning.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawDispatcherSite {
    /// Virtual address of the pattern (base + offset).
    pub address: u64,
    /// Byte offset within the supplied buffer.
    pub offset: usize,
    /// Pattern kind that was matched.
    pub kind: RawDispatcherKind,
    /// Jump table entries extracted for this site (empty when not applicable).
    pub table_entries: Vec<u64>,
}

/// Lightweight dispatcher detector that works directly on raw byte slices.
///
/// Complements [`dispatcher_detector::DispatcherDetector`] with additional
/// x86-64 patterns and jump-table extraction.
pub struct VmDispatcherDetector;

impl VmDispatcherDetector {
    /// Scan `code` (mapped at virtual address `base`) for dispatcher patterns.
    ///
    /// Searches for:
    /// - `FF 24 CD` — `jmp [reg*8 + disp32]` (dense switch table, scale=8)
    /// - `FF E0` / `FF E1` — `jmp rax` / `jmp rcx` after a nearby table load
    /// - `call $+5; pop reg; add reg, imm` — VM stub IP-fixup chain
    #[must_use]
    pub fn detect_in_bytes(code: &[u8], base: u64) -> Vec<VmDispatcher> {
        let mut out: Vec<VmDispatcher> = Vec::new();
        let len = code.len();

        // ── Pattern A: FF 24 CD xx xx xx xx  (jmp [reg*8 + disp32]) ──────────
        // SIB byte 0xCD = scale=8, index=rcx, base=rbp/none
        // Cap: at most 4096 dispatcher sites per pattern to prevent memory exhaustion
        // on attacker-supplied inputs that contain the pattern at every offset.
        const MAX_DISPATCHERS_PER_PATTERN: usize = 4096;
        if len >= 7 {
            for i in 0..len - 6 {
                if out.len() >= MAX_DISPATCHERS_PER_PATTERN {
                    break;
                }
                if code[i] == 0xFF && code[i + 1] == 0x24 && code[i + 2] == 0xCD {
                    // Extract the 32-bit table displacement
                    let disp =
                        u64::from(u32::from_le_bytes([code[i + 3], code[i + 4], code[i + 5], code[i + 6]]));
                    // Heuristic: try to interpret disp as a file offset.
                    // Only extract the table if the displacement maps inside the buffer.
                    let entries = if disp >= base {
                        let table_offset = (disp - base) as usize;
                        Self::extract_jump_table_entries(code, table_offset, 256, 8)
                    } else {
                        Vec::new()
                    };
                    let handler_count = entries.len().max(1);
                    out.push(VmDispatcher {
                        offset: i,
                        size: 7,
                        kind: dispatcher_detector::DispatcherKind::JumpTable,
                        confidence: 85,
                        registers: vec![dispatcher_detector::VmRegister::new(
                            1,
                            64,
                            dispatcher_detector::RegisterRole::VirtualIp,
                        )],
                        handler_count,
                        flags: dispatcher_detector::DispatcherFlags::default(),
                        description: format!(
                            "FF 24 CD indirect-indexed jmp at {:#x} (table rva={:#x}, {} entries)",
                            base + i as u64,
                            disp,
                            handler_count
                        ),
                    });
                }
            }
        }

        // ── Pattern B: FF E0 (jmp rax) or FF E1 (jmp rcx) ───────────────────
        // Preceded within 32 bytes by a MOV load from a table base
        if len >= 2 {
            let pattern_b_start = out.len();
            for i in 0..len - 1 {
                if out.len() - pattern_b_start >= MAX_DISPATCHERS_PER_PATTERN {
                    break;
                }
                let is_computed_jmp =
                    code[i] == 0xFF && (code[i + 1] == 0xE0 || code[i + 1] == 0xE1);
                if !is_computed_jmp {
                    continue;
                }
                // Look back for a table-load pattern (REX.W MOV or LEA in the 32-byte window)
                let look_back_start = i.saturating_sub(32);
                let pre = &code[look_back_start..i];
                let has_table_load = pre.windows(3).any(|w| {
                    // REX.W MOV r64, [r64+disp]: 48 8B ...
                    // REX.W LEA r64, [rip+disp]: 48 8D 05 ...
                    (w[0] == 0x48 && (w[1] == 0x8B || w[1] == 0x8D))
                    // plain MOV r32, [r32+disp]: 8B ...
                    || w[0] == 0x8B
                });
                let confidence = if has_table_load { 75 } else { 55 };
                out.push(VmDispatcher {
                    offset: i,
                    size: 2,
                    kind: dispatcher_detector::DispatcherKind::JumpTable,
                    confidence,
                    registers: vec![dispatcher_detector::VmRegister::new(
                        0,
                        64,
                        dispatcher_detector::RegisterRole::VirtualIp,
                    )],
                    handler_count: 256,
                    flags: dispatcher_detector::DispatcherFlags::default(),
                    description: format!(
                        "computed-jmp FF E{:X} at {:#x} (table_load_hint={})",
                        code[i + 1] & 0xF,
                        base + i as u64,
                        has_table_load
                    ),
                });
            }
        }

        // ── Pattern C: call $+5 ; pop reg ; add reg, imm ─────────────────────
        // call $+5: E8 00 00 00 00
        // pop rax..rdi: 58..5F  (or 41 58..5F for r8..r15)
        // add reg, imm32: 48 81 C0..C7 xx xx xx xx
        if len >= 13 {
            let pattern_c_start = out.len();
            for i in 0..=len - 13 {
                if out.len() - pattern_c_start >= MAX_DISPATCHERS_PER_PATTERN {
                    break;
                }
                // call $+5
                if code[i] != 0xE8
                    || code[i + 1] != 0x00
                    || code[i + 2] != 0x00
                    || code[i + 3] != 0x00
                    || code[i + 4] != 0x00
                {
                    continue;
                }
                // pop reg8 (58-5F) immediately after
                let pop_byte = code[i + 5];
                if !(0x58..=0x5F).contains(&pop_byte) {
                    continue;
                }
                // REX.W add reg, imm32: 48 81 C0|C1|...|C7 imm32
                if code[i + 6] == 0x48 && code[i + 7] == 0x81 {
                    let modrm = code[i + 8];
                    // ModRM: mod=11 (/0 = ADD), reg field = 0
                    if (modrm & 0xF8) == 0xC0 {
                        let addend = u32::from_le_bytes([
                            code[i + 9],
                            code[i + 10],
                            code[i + 11],
                            code[i + 12],
                        ]);
                        out.push(VmDispatcher {
                            offset: i,
                            size: 13,
                            kind: dispatcher_detector::DispatcherKind::InterpreterLoop,
                            confidence: 80,
                            registers: vec![dispatcher_detector::VmRegister::new(
                                pop_byte - 0x58,
                                64,
                                dispatcher_detector::RegisterRole::BytecodeBase,
                            )],
                            handler_count: 0,
                            flags: dispatcher_detector::DispatcherFlags::default(),
                            description: format!(
                                "call+pop+add VM stub at {:#x}: pop r{}, add +{:#x}",
                                base + i as u64,
                                pop_byte - 0x58,
                                addend
                            ),
                        });
                    }
                }
            }
        }

        out
    }

    /// Read `count` pointers of `addr_size` bytes from `data[table_offset..]`.
    ///
    /// Filters out entries whose virtual address falls outside
    /// `[base, base + data.len()]`.
    #[must_use]
    pub fn extract_jump_table_entries(
        data: &[u8],
        table_offset: usize,
        count: usize,
        addr_size: u8,
    ) -> Vec<u64> {
        let step = addr_size as usize;
        let mut entries = Vec::with_capacity(count.min(1024));
        let base_hint: u64 = 0; // conservative: accept any non-zero entry

        for i in 0..count {
            let off = table_offset + i * step;
            if step == 0 || off + step > data.len() {
                break;
            }
            let addr: u64 = match step {
                2 => u64::from(u16::from_le_bytes([data[off], data[off + 1]])),
                4 => u64::from(u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]])),
                8 => u64::from_le_bytes([
                    data[off],
                    data[off + 1],
                    data[off + 2],
                    data[off + 3],
                    data[off + 4],
                    data[off + 5],
                    data[off + 6],
                    data[off + 7],
                ]),
                _ => break,
            };
            // Plausibility filter: non-zero and within a 4 GiB window of data
            let data_len = data.len() as u64;
            let plausible = addr != 0
                && addr != u64::MAX
                && (addr >= base_hint && addr < base_hint + data_len.max(0x1_0000_0000));
            if plausible {
                entries.push(addr);
            } else {
                // Stop at the first implausible entry — table has ended
                break;
            }
        }
        entries
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// HandlerSemantic — rich handler classification enum
// ═════════════════════════════════════════════════════════════════════════════

/// Source of a VM PUSH operation.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PushSrc {
    /// Push an inline constant from the bytecode stream.
    Constant(u64),
    /// Push a virtual register value.
    VirtualReg(u8),
    /// Push the value read from a memory address.
    Memory,
}

/// Destination of a VM POP operation.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PopDst {
    /// Pop into a virtual register.
    VirtualReg(u8),
    /// Pop to a memory address.
    Memory,
}

/// Arithmetic / logical binary operation kind.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BinOpKind {
    Add,
    Sub,
    Mul,
    Div,
    And,
    Or,
    Xor,
    Shl,
    Shr,
    Sar,
    Rol,
    Ror,
}

impl std::fmt::Display for BinOpKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

/// Rich semantic description of a single VM handler.
///
/// This is the primary carrier of handler intent used by the ISA synthesiser
/// and the bytecode disassembler.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum HandlerSemantic {
    /// Push a constant, register, or memory value onto the VM stack.
    Push(PushSrc),
    /// Pop from the VM stack into a register or memory.
    Pop(PopDst),
    /// Binary arithmetic / logical operation on the top two stack items.
    BinOp(BinOpKind),
    /// Load `N` bytes from `[addr]` and push the result.
    Load(u8),
    /// Store `N` bytes from the stack top to `[addr]`.
    Store(u8),
    /// Compare the top two stack items and update VM flags.
    Cmp,
    /// Conditional branch based on the VM flags / stack top.
    Branch,
    /// Call to an address popped from the VM stack.
    Call,
    /// Return from the current VM frame.
    Ret,
    /// Halt / stop execution of the virtual machine.
    Halt,
    /// Advance the virtual instruction pointer by `N` bytes.
    IpAdvance(usize),
    /// Semantics could not be determined.
    Unknown,
}

impl HandlerSemantic {
    /// Return `true` if this semantic modifies control flow.
    #[must_use]
    pub const fn is_control_flow(&self) -> bool {
        matches!(self, Self::Branch | Self::Call | Self::Ret | Self::Halt)
    }

    /// Return `true` if this semantic accesses memory.
    #[must_use]
    pub const fn accesses_memory(&self) -> bool {
        matches!(
            self,
            Self::Load(_)
                | Self::Store(_)
                | Self::Push(PushSrc::Memory)
                | Self::Pop(PopDst::Memory)
        )
    }

    /// Suggest a short mnemonic for this semantic.
    #[must_use]
    pub fn suggest_mnemonic(&self) -> &'static str {
        suggest_mnemonic(self)
    }
}

impl std::fmt::Display for HandlerSemantic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Push(PushSrc::Constant(v)) => write!(f, "VPUSH #{v:#x}"),
            Self::Push(PushSrc::VirtualReg(r)) => write!(f, "VPUSH vr{r}"),
            Self::Push(PushSrc::Memory) => write!(f, "VPUSH [mem]"),
            Self::Pop(PopDst::VirtualReg(r)) => write!(f, "VPOP  vr{r}"),
            Self::Pop(PopDst::Memory) => write!(f, "VPOP  [mem]"),
            Self::BinOp(op) => write!(f, "V{op}"),
            Self::Load(n) => write!(f, "VLOAD{}  [addr]", n * 8),
            Self::Store(n) => write!(f, "VSTORE{} [addr]", n * 8),
            Self::Cmp => write!(f, "VCMP"),
            Self::Branch => write!(f, "VBRANCH"),
            Self::Call => write!(f, "VCALL"),
            Self::Ret => write!(f, "VRET"),
            Self::Halt => write!(f, "VHALT"),
            Self::IpAdvance(n) => write!(f, "VIP+={n}"),
            Self::Unknown => write!(f, "VUNK"),
        }
    }
}

/// Return a short static mnemonic for the given semantic.
#[must_use]
pub const fn suggest_mnemonic(sem: &HandlerSemantic) -> &'static str {
    match sem {
        HandlerSemantic::Push(_) => "VPUSH",
        HandlerSemantic::Pop(_) => "VPOP",
        HandlerSemantic::BinOp(BinOpKind::Add) => "VADD",
        HandlerSemantic::BinOp(BinOpKind::Sub) => "VSUB",
        HandlerSemantic::BinOp(BinOpKind::Mul) => "VMUL",
        HandlerSemantic::BinOp(BinOpKind::Div) => "VDIV",
        HandlerSemantic::BinOp(BinOpKind::And) => "VAND",
        HandlerSemantic::BinOp(BinOpKind::Or) => "VOR",
        HandlerSemantic::BinOp(BinOpKind::Xor) => "VXOR",
        HandlerSemantic::BinOp(BinOpKind::Shl) => "VSHL",
        HandlerSemantic::BinOp(BinOpKind::Shr) => "VSHR",
        HandlerSemantic::BinOp(BinOpKind::Sar) => "VSAR",
        HandlerSemantic::BinOp(BinOpKind::Rol) => "VROL",
        HandlerSemantic::BinOp(BinOpKind::Ror) => "VROR",
        HandlerSemantic::Load(_) => "VLOAD",
        HandlerSemantic::Store(_) => "VSTORE",
        HandlerSemantic::Cmp => "VCMP",
        HandlerSemantic::Branch => "VBRANCH",
        HandlerSemantic::Call => "VCALL",
        HandlerSemantic::Ret => "VRET",
        HandlerSemantic::Halt => "VHALT",
        HandlerSemantic::IpAdvance(_) => "VIPADVANCE",
        HandlerSemantic::Unknown => "VUNK",
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// VmIsa — synthesised instruction set architecture
// ═════════════════════════════════════════════════════════════════════════════

/// One instruction definition within the synthesised VM ISA.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmInstructionDef {
    /// Opcode byte (0x00–0xFF).
    pub opcode: u8,
    /// Human-readable mnemonic suggested from the semantic.
    pub mnemonic: String,
    /// Rich semantic description of this instruction.
    pub semantic: HandlerSemantic,
    /// Number of immediate operand bytes that follow the opcode in bytecode.
    pub operand_bytes: usize,
}

impl VmInstructionDef {
    /// Construct a definition from a semantic, deriving defaults for the
    /// mnemonic and operand width.
    #[must_use]
    pub fn new(opcode: u8, semantic: HandlerSemantic) -> Self {
        let mnemonic = semantic.suggest_mnemonic().to_owned();
        let operand_bytes = Self::default_operand_bytes(&semantic);
        Self {
            opcode,
            mnemonic,
            semantic,
            operand_bytes,
        }
    }

    const fn default_operand_bytes(sem: &HandlerSemantic) -> usize {
        match sem {
            HandlerSemantic::Push(PushSrc::Constant(_)) => 8,
            HandlerSemantic::Push(PushSrc::VirtualReg(_)) => 1,
            HandlerSemantic::Pop(PopDst::VirtualReg(_)) => 1,
            HandlerSemantic::Load(n) | HandlerSemantic::Store(n) => *n as usize,
            HandlerSemantic::IpAdvance(_) => 4,
            HandlerSemantic::Branch => 4,
            _ => 0,
        }
    }
}

impl std::fmt::Display for VmInstructionDef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "[{:#04x}] {:12}  ; {} (operand_bytes={})",
            self.opcode, self.mnemonic, self.semantic, self.operand_bytes
        )
    }
}

/// Synthesised instruction set architecture of a detected virtual machine.
///
/// Maps opcode byte → [`VmInstructionDef`].
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct VmIsa {
    /// All known handler definitions, keyed by opcode byte.
    pub handlers: HashMap<u8, VmInstructionDef>,
}

impl VmIsa {
    /// Create an empty ISA.
    #[must_use]
    pub fn new() -> Self {
        Self {
            handlers: HashMap::new(),
        }
    }

    /// Register a handler definition, replacing any existing entry for the
    /// same opcode.
    pub fn register(&mut self, def: VmInstructionDef) {
        self.handlers.insert(def.opcode, def);
    }

    /// Look up a handler by opcode, returning `None` for unknown opcodes.
    #[must_use]
    pub fn lookup(&self, opcode: u8) -> Option<&VmInstructionDef> {
        self.handlers.get(&opcode)
    }

    /// Return all handlers sorted by opcode for deterministic output.
    #[must_use]
    pub fn sorted_handlers(&self) -> Vec<&VmInstructionDef> {
        let mut v: Vec<&VmInstructionDef> = self.handlers.values().collect();
        v.sort_by_key(|d| d.opcode);
        v
    }

    /// Emit a human-readable listing of the entire ISA.
    #[must_use]
    pub fn listing(&self) -> String {
        self.sorted_handlers()
            .iter()
            .map(std::string::ToString::to_string)
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Return the number of known handlers.
    #[must_use]
    pub fn len(&self) -> usize {
        self.handlers.len()
    }

    /// Return `true` when no handlers have been registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.handlers.is_empty()
    }

    /// Suggest a mnemonic for the given semantic value.
    #[must_use]
    pub fn suggest_mnemonic(sem: &HandlerSemantic) -> &'static str {
        suggest_mnemonic(sem)
    }

    /// Build a default ISA covering the standard bytecode encoding used by
    /// [`VmLifter`].  Opcodes 0x01–0x09 are mapped to their known semantics.
    #[must_use]
    pub fn default_lifter_isa() -> Self {
        let mut isa = Self::new();
        let defs: &[(u8, HandlerSemantic, usize)] = &[
            (0x01, HandlerSemantic::BinOp(BinOpKind::Add), 2),
            (0x02, HandlerSemantic::BinOp(BinOpKind::Sub), 2),
            (0x03, HandlerSemantic::Push(PushSrc::VirtualReg(0)), 1),
            (0x04, HandlerSemantic::Pop(PopDst::VirtualReg(0)), 1),
            (0x05, HandlerSemantic::Load(4), 6),
            (0x06, HandlerSemantic::Store(4), 6),
            (0x07, HandlerSemantic::Halt, 0),
            (0x08, HandlerSemantic::Load(4), 5),
            (0x09, HandlerSemantic::Push(PushSrc::Constant(0)), 4),
        ];
        for &(op, ref sem, ob) in defs {
            let mut def = VmInstructionDef::new(op, sem.clone());
            def.operand_bytes = ob;
            isa.register(def);
        }
        isa
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// VmBytecodeDisassembler
// ═════════════════════════════════════════════════════════════════════════════

/// A single disassembled VM instruction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmInstruction {
    /// Byte offset of this instruction within the bytecode buffer.
    pub offset: usize,
    /// Opcode byte.
    pub opcode: u8,
    /// Decoded immediate operands (up to the `operand_bytes` count).
    pub operands: Vec<u64>,
    /// Resolved mnemonic (from the ISA table, or `"VUNK_{:02X}"`).
    pub mnemonic: String,
}

impl std::fmt::Display for VmInstruction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let ops: Vec<String> = self.operands.iter().map(|o| format!("{o:#x}")).collect();
        if ops.is_empty() {
            write!(
                f,
                "{:>6}  {:12}",
                format!("{:#06x}", self.offset),
                self.mnemonic
            )
        } else {
            write!(
                f,
                "{:>6}  {:12}  {}",
                format!("{:#06x}", self.offset),
                self.mnemonic,
                ops.join(", ")
            )
        }
    }
}

/// Error type returned when bytecode decoding fails.
#[derive(Debug, Clone, thiserror::Error)]
pub enum DecodeError {
    /// The buffer ends before all operand bytes of an instruction have been read.
    #[error(
        "truncated instruction at offset {offset:#x}: opcode {opcode:#04x} \
         requires {expected_operand_bytes} operand byte(s) but only \
         {available_bytes} remain in the buffer"
    )]
    TruncatedInstruction {
        /// Byte offset of the truncated instruction.
        offset: usize,
        /// Opcode byte of the truncated instruction.
        opcode: u8,
        /// Number of operand bytes the ISA definition requires.
        expected_operand_bytes: usize,
        /// Number of bytes actually remaining after the opcode.
        available_bytes: usize,
    },
}

/// Disassembles raw bytecode according to a [`VmIsa`].
pub struct VmBytecodeDisassembler;

impl VmBytecodeDisassembler {
    /// Decode `bytecode` using the supplied ISA table.
    ///
    /// Unknown opcodes are emitted as `VUNK_xx` with zero operands, and
    /// decoding advances by one byte so as not to get stuck.
    ///
    /// # Errors
    /// Returns [`DecodeError::TruncatedInstruction`] if the bytecode buffer
    /// ends mid-instruction (i.e. fewer operand bytes are available than the
    /// ISA definition requires).
    pub fn disassemble(
        bytecode: &[u8],
        isa: &VmIsa,
    ) -> std::result::Result<Vec<VmInstruction>, DecodeError> {
        let mut instrs = Vec::new();
        let mut pc = 0usize;

        while pc < bytecode.len() {
            let opcode = bytecode[pc];
            let offset = pc;
            pc += 1;

            match isa.lookup(opcode) {
                Some(def) => {
                    let ob = def.operand_bytes;
                    if pc + ob > bytecode.len() {
                        return Err(DecodeError::TruncatedInstruction {
                            offset,
                            opcode,
                            expected_operand_bytes: ob,
                            available_bytes: bytecode.len().saturating_sub(pc),
                        });
                    }
                    let operands = Self::read_operands(bytecode, pc, ob, &def.semantic);
                    pc += ob;
                    instrs.push(VmInstruction {
                        offset,
                        opcode,
                        operands,
                        mnemonic: def.mnemonic.clone(),
                    });
                }
                None => {
                    instrs.push(VmInstruction {
                        offset,
                        opcode,
                        operands: vec![],
                        mnemonic: format!("VUNK_{opcode:02X}"),
                    });
                }
            }
        }

        Ok(instrs)
    }

    /// Convert a list of `VmInstruction` values to a printable disassembly.
    #[must_use]
    pub fn to_text(instrs: &[VmInstruction]) -> String {
        instrs
            .iter()
            .map(std::string::ToString::to_string)
            .collect::<Vec<_>>()
            .join("\n")
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    fn read_operands(buf: &[u8], pc: usize, ob: usize, sem: &HandlerSemantic) -> Vec<u64> {
        if ob == 0 || pc >= buf.len() {
            return vec![];
        }
        let available = (buf.len() - pc).min(ob);
        // For binary-op instructions that take two 1-byte register indices,
        // emit them as two separate operands.
        match sem {
            HandlerSemantic::BinOp(_) if ob == 2 && available >= 2 => {
                vec![u64::from(buf[pc]), u64::from(buf[pc + 1])]
            }
            HandlerSemantic::Push(PushSrc::VirtualReg(_))
            | HandlerSemantic::Pop(PopDst::VirtualReg(_))
                if ob == 1 && available >= 1 =>
            {
                vec![u64::from(buf[pc])]
            }
            // For load/store with 6-byte operands: 2 register bytes + 4-byte imm
            HandlerSemantic::Load(_) | HandlerSemantic::Store(_) if ob == 6 && available >= 6 => {
                let imm = u32::from_le_bytes([buf[pc + 2], buf[pc + 3], buf[pc + 4], buf[pc + 5]]);
                vec![u64::from(buf[pc]), u64::from(buf[pc + 1]), u64::from(imm)]
            }
            // Load-immediate: 1 reg byte + 4-byte imm
            HandlerSemantic::Load(_) if ob == 5 && available >= 5 => {
                let imm = u32::from_le_bytes([buf[pc + 1], buf[pc + 2], buf[pc + 3], buf[pc + 4]]);
                vec![u64::from(buf[pc]), u64::from(imm)]
            }
            // Push-immediate: 4-byte imm
            HandlerSemantic::Push(PushSrc::Constant(_)) if ob == 4 && available >= 4 => {
                let imm = u32::from_le_bytes([buf[pc], buf[pc + 1], buf[pc + 2], buf[pc + 3]]);
                vec![u64::from(imm)]
            }
            // Branch / IpAdvance: 4-byte target offset
            HandlerSemantic::Branch | HandlerSemantic::IpAdvance(_)
                if ob == 4 && available >= 4 =>
            {
                let v = u32::from_le_bytes([buf[pc], buf[pc + 1], buf[pc + 2], buf[pc + 3]]);
                vec![u64::from(v)]
            }
            _ => {
                // Generic: read `available` bytes as a single little-endian value
                let mut raw = 0u64;
                for (i, &b) in buf[pc..pc + available].iter().enumerate() {
                    raw |= u64::from(b) << (i * 8);
                }
                vec![raw]
            }
        }
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// VmLifterPipeline — end-to-end analysis and lifting
// ═════════════════════════════════════════════════════════════════════════════

/// Summary produced by a full VM detection run.
#[derive(Debug, Serialize, Deserialize)]
pub struct VmLiftReport {
    /// Number of dispatcher sites detected in the binary.
    pub dispatchers_found: usize,
    /// Total number of distinct handler entries across all dispatchers.
    pub total_handlers: usize,
    /// The synthesised ISA (may be empty if detection failed).
    pub isa: VmIsa,
    /// Human-readable notes produced during analysis.
    pub analysis_notes: Vec<String>,
}

/// Drives the full VM lifting pipeline:
/// 1. Dispatcher detection
/// 2. ISA synthesis
/// 3. Bytecode disassembly + LLIL-style text lifting
pub struct VmLifterPipeline;

impl VmLifterPipeline {
    /// Scan `code` (mapped at `base`) for VM dispatchers and return a
    /// [`VmLiftReport`] summarising what was found.
    #[must_use]
    pub fn detect_and_report(code: &[u8], base: u64) -> VmLiftReport {
        let mut notes: Vec<String> = Vec::new();

        // ── Phase 1: raw byte-pattern dispatcher detection ─────────────────
        let raw_dispatchers = VmDispatcherDetector::detect_in_bytes(code, base);
        notes.push(format!(
            "Phase 1: raw pattern scan found {} dispatcher site(s)",
            raw_dispatchers.len()
        ));

        // ── Phase 2: structural dispatcher detection ───────────────────────
        let structural = dispatcher_detector::DispatcherDetector::new()
            .with_min_confidence(50)
            .detect(code);
        notes.push(format!(
            "Phase 2: structural analysis found {} dispatcher(s)",
            structural.len()
        ));

        // Merge and deduplicate by offset proximity (within 16 bytes)
        let mut all_dispatchers: Vec<&VmDispatcher> =
            raw_dispatchers.iter().chain(structural.iter()).collect();
        all_dispatchers.sort_by_key(|d| d.offset);
        let mut merged: Vec<VmDispatcher> = Vec::new();
        for d in all_dispatchers {
            if let Some(last) = merged.last()
                && d.offset.abs_diff(last.offset) < 16 {
                    // keep the higher-confidence one
                    if d.confidence > last.confidence {
                        *merged.last_mut().unwrap() = d.clone();
                    }
                    continue;
                }
            merged.push(d.clone());
        }

        let dispatchers_found = merged.len();
        let total_handlers: usize = merged.iter().map(|d| d.handler_count.max(1)).sum();

        // ── Phase 3: ISA synthesis from the default lifter encoding ────────
        // Build a baseline ISA from the standard encoding; a real implementation
        // would derive this from the extracted handler bytes.
        let isa = VmIsa::default_lifter_isa();
        notes.push(format!(
            "Phase 3: synthesised ISA with {} handler definitions",
            isa.len()
        ));

        for d in &merged {
            notes.push(format!(
                "  dispatcher @ {:#x}  kind={:?}  confidence={}  handlers~{}",
                base + d.offset as u64,
                d.kind,
                d.confidence,
                d.handler_count
            ));
        }

        if dispatchers_found == 0 {
            notes.push("WARNING: no dispatchers detected — binary may not contain a VM or pattern is novel".to_owned());
        }

        VmLiftReport {
            dispatchers_found,
            total_handlers,
            isa,
            analysis_notes: notes,
        }
    }

    /// Run the full pipeline: detect dispatchers, build ISA, disassemble
    /// `bytecode`, and return lifted LLIL-style text lines.
    ///
    /// # Errors
    /// Returns an error if the bytecode buffer is empty.
    pub fn full_pipeline(code: &[u8], base: u64, bytecode: &[u8]) -> Result<Vec<String>> {
        if bytecode.is_empty() {
            anyhow::bail!("empty bytecode buffer: nothing to disassemble");
        }

        let report = Self::detect_and_report(code, base);
        let mut lines: Vec<String> = Vec::new();

        // Header
        lines.push(format!("; VM Lift Report — base={base:#x}"));
        lines.push(format!(
            "; dispatchers={} total_handlers={}",
            report.dispatchers_found, report.total_handlers
        ));
        lines.push(String::new());

        // ISA listing
        lines.push("; ── ISA ──────────────────────────────────────────────".to_owned());
        for handler in report.isa.sorted_handlers() {
            lines.push(format!(";  {handler}"));
        }
        lines.push(String::new());

        // Disassemble
        lines.push("; ── Disassembly ──────────────────────────────────────".to_owned());
        let instrs = VmBytecodeDisassembler::disassemble(bytecode, &report.isa)
            .map_err(|e| anyhow::anyhow!("bytecode decode error: {e}"))?;
        if instrs.is_empty() {
            lines.push(";  (no instructions decoded)".to_owned());
        }
        for instr in &instrs {
            // Emit LLIL-style comment: offset  mnemonic  operands  ; pseudo-code
            let pseudo = match report.isa.lookup(instr.opcode) {
                Some(def) => def.semantic.to_string(),
                None => "unknown".to_owned(),
            };
            lines.push(format!("{instr}  ; {pseudo}"));
        }
        lines.push(String::new());

        // Analysis notes
        lines.push("; ── Analysis Notes ───────────────────────────────────".to_owned());
        for note in &report.analysis_notes {
            lines.push(format!("; {note}"));
        }

        Ok(lines)
    }
}

/// Execute deobfuscation pass for VMLIFT and return the pseudo IL as a Vec<String>.
///
/// Previously this printed to stdout — that broke callers using stdio for structured
/// IO (e.g. MCP JSON-RPC). It now returns the lines so the caller decides output.
#[must_use]
/// Lift `bytecode` and render it as pseudo-IL lines.
///
/// Returns an empty vector when the bytes do not lift — an unliftable blob has
/// no pseudo-IL, and saying so with an empty result keeps the caller from
/// distinguishing "failed" from "lifted to nothing" only by a side channel.
///
/// ⚠ This used to take no argument and lift a hardcoded `vec![0x07]`, so every
/// caller got the pseudo-IL of one byte nobody chose. Its MCP wrapper then
/// discarded even that and answered `{"ok": true}` unconditionally — a tool
/// that reported success for an analysis it never performed on input it never
/// received.
pub fn run_pass(bytecode: &[u8]) -> Vec<String> {
    VmLifter::lift_to_instructions(bytecode)
        .map(|instrs| VmLifter::to_pseudo_il(&instrs))
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lift_single_instructions() {
        // Add r1, r2
        assert_eq!(
            VmLifter::lift_to_instructions(&[0x01, 0x01, 0x02]),
            Ok(vec![GuestInstruction {
                opcode: GuestOpcode::Add,
                reg_dst: Some(1),
                reg_src: Some(2),
                imm: None,
            }])
        );

        // Sub r3, r4
        assert_eq!(
            VmLifter::lift_to_instructions(&[0x02, 0x03, 0x04]),
            Ok(vec![GuestInstruction {
                opcode: GuestOpcode::Sub,
                reg_dst: Some(3),
                reg_src: Some(4),
                imm: None,
            }])
        );

        // Push r5
        assert_eq!(
            VmLifter::lift_to_instructions(&[0x03, 0x05]),
            Ok(vec![GuestInstruction {
                opcode: GuestOpcode::Push,
                reg_dst: None,
                reg_src: Some(5),
                imm: None,
            }])
        );

        // Pop r6
        assert_eq!(
            VmLifter::lift_to_instructions(&[0x04, 0x06]),
            Ok(vec![GuestInstruction {
                opcode: GuestOpcode::Pop,
                reg_dst: Some(6),
                reg_src: None,
                imm: None,
            }])
        );

        // Load r7, [r8 + 0x12345678]
        assert_eq!(
            VmLifter::lift_to_instructions(&[0x05, 0x07, 0x08, 0x78, 0x56, 0x34, 0x12]),
            Ok(vec![GuestInstruction {
                opcode: GuestOpcode::Load,
                reg_dst: Some(7),
                reg_src: Some(8),
                imm: Some(0x12345678),
            }])
        );

        // Store [r9 + 0x87654321], r10
        assert_eq!(
            VmLifter::lift_to_instructions(&[0x06, 0x09, 0x0A, 0x21, 0x43, 0x65, 0x87]),
            Ok(vec![GuestInstruction {
                opcode: GuestOpcode::Store,
                reg_dst: Some(9),
                reg_src: Some(10),
                imm: Some(0x87654321),
            }])
        );

        // Halt
        assert_eq!(
            VmLifter::lift_to_instructions(&[0x07]),
            Ok(vec![GuestInstruction {
                opcode: GuestOpcode::Halt,
                reg_dst: None,
                reg_src: None,
                imm: None,
            }])
        );

        // LoadImm r1, 0x1000
        assert_eq!(
            VmLifter::lift_to_instructions(&[0x08, 0x01, 0x00, 0x10, 0x00, 0x00]),
            Ok(vec![GuestInstruction {
                opcode: GuestOpcode::Load,
                reg_dst: Some(1),
                reg_src: None,
                imm: Some(0x1000),
            }])
        );

        // PushImm 0x2000
        assert_eq!(
            VmLifter::lift_to_instructions(&[0x09, 0x00, 0x20, 0x00, 0x00]),
            Ok(vec![GuestInstruction {
                opcode: GuestOpcode::Push,
                reg_dst: None,
                reg_src: None,
                imm: Some(0x2000),
            }])
        );
    }

    #[test]
    fn test_lift_complex_program() {
        // Program logic:
        // LoadImm r0, 42
        // LoadImm r1, 10
        // Add r0, r1
        // Push r0
        // Pop r2
        // Store [r0 + 0x100], r2
        // Halt
        let bytecode = vec![
            0x08, 0x00, 0x2A, 0x00, 0x00, 0x00, // LoadImm r0, 42
            0x08, 0x01, 0x0A, 0x00, 0x00, 0x00, // LoadImm r1, 10
            0x01, 0x00, 0x01, // Add r0, r1
            0x03, 0x00, // Push r0
            0x04, 0x02, // Pop r2
            0x06, 0x00, 0x02, 0x00, 0x01, 0x00, 0x00, // Store [r0 + 0x100], r2
            0x07, // Halt
        ];

        let instrs = VmLifter::lift_to_instructions(&bytecode).unwrap();
        assert_eq!(instrs.len(), 7);

        let pseudo = VmLifter::to_pseudo_il(&instrs);
        assert_eq!(
            pseudo,
            vec![
                "LOAD r0, 0x2a",
                "LOAD r1, 0xa",
                "ADD r0, r1",
                "PUSH r0",
                "POP r2",
                "STORE [r0 + 0x100], r2",
                "HALT"
            ]
        );
    }

    #[test]
    fn test_error_handling() {
        // Unexpected end of bytecode for Add instruction
        assert_eq!(
            VmLifter::lift_to_instructions(&[0x01, 0x01]),
            Err("Unexpected end of bytecode for Add instruction")
        );

        // Unknown opcode
        assert_eq!(
            VmLifter::lift_to_instructions(&[0xFF]),
            Err("Unknown opcode in bytecode")
        );
    }

    #[test]
    fn test_display_edge_cases() {
        let instr = GuestInstruction {
            opcode: GuestOpcode::Load,
            reg_dst: None,
            reg_src: None,
            imm: None,
        };
        assert_eq!(instr.to_string(), "LOAD ?, ?");

        let instr = GuestInstruction {
            opcode: GuestOpcode::Store,
            reg_dst: None,
            reg_src: None,
            imm: None,
        };
        assert_eq!(instr.to_string(), "STORE [?], ?");

        let instr = GuestInstruction {
            opcode: GuestOpcode::Push,
            reg_dst: None,
            reg_src: None,
            imm: None,
        };
        assert_eq!(instr.to_string(), "PUSH ?");
    }

    // ── Additional tests ─────────────────────────────────────────────────────

    #[test]
    fn test_lift_empty_bytecode() {
        let result = VmLifter::lift_to_instructions(&[]);
        assert_eq!(result, Ok(vec![]));
    }

    #[test]
    fn test_lift_halt_only() {
        let result = VmLifter::lift_to_instructions(&[0x07]);
        assert!(result.is_ok());
        let instrs = result.unwrap();
        assert_eq!(instrs.len(), 1);
        assert_eq!(instrs[0].opcode, GuestOpcode::Halt);
    }

    #[test]
    fn test_lift_add_display() {
        let instr = GuestInstruction {
            opcode: GuestOpcode::Add,
            reg_dst: Some(0),
            reg_src: Some(1),
            imm: None,
        };
        assert_eq!(instr.to_string(), "ADD r0, r1");
    }

    #[test]
    fn test_lift_sub_display() {
        let instr = GuestInstruction {
            opcode: GuestOpcode::Sub,
            reg_dst: Some(2),
            reg_src: Some(3),
            imm: None,
        };
        assert_eq!(instr.to_string(), "SUB r2, r3");
    }

    #[test]
    fn test_lift_halt_display() {
        let instr = GuestInstruction {
            opcode: GuestOpcode::Halt,
            reg_dst: None,
            reg_src: None,
            imm: None,
        };
        assert_eq!(instr.to_string(), "HALT");
    }

    #[test]
    fn test_lift_load_with_zero_imm() {
        let instr = GuestInstruction {
            opcode: GuestOpcode::Load,
            reg_dst: Some(0),
            reg_src: Some(1),
            imm: Some(0),
        };
        assert_eq!(instr.to_string(), "LOAD r0, [r1]");
    }

    #[test]
    fn test_lift_load_with_nonzero_imm() {
        let instr = GuestInstruction {
            opcode: GuestOpcode::Load,
            reg_dst: Some(0),
            reg_src: Some(1),
            imm: Some(0x10),
        };
        assert_eq!(instr.to_string(), "LOAD r0, [r1 + 0x10]");
    }

    #[test]
    fn test_lift_load_imm_only() {
        let instr = GuestInstruction {
            opcode: GuestOpcode::Load,
            reg_dst: Some(0),
            reg_src: None,
            imm: Some(0x42),
        };
        assert_eq!(instr.to_string(), "LOAD r0, 0x42");
    }

    #[test]
    fn test_lift_store_zero_imm() {
        let instr = GuestInstruction {
            opcode: GuestOpcode::Store,
            reg_dst: Some(0),
            reg_src: Some(1),
            imm: Some(0),
        };
        assert_eq!(instr.to_string(), "STORE [r0], r1");
    }

    #[test]
    fn test_lift_store_nonzero_imm() {
        let instr = GuestInstruction {
            opcode: GuestOpcode::Store,
            reg_dst: Some(0),
            reg_src: Some(1),
            imm: Some(0x20),
        };
        assert_eq!(instr.to_string(), "STORE [r0 + 0x20], r1");
    }

    #[test]
    fn test_lift_push_imm() {
        let instr = GuestInstruction {
            opcode: GuestOpcode::Push,
            reg_dst: None,
            reg_src: None,
            imm: Some(0x1234),
        };
        assert_eq!(instr.to_string(), "PUSH 0x1234");
    }

    #[test]
    fn test_lift_push_reg() {
        let instr = GuestInstruction {
            opcode: GuestOpcode::Push,
            reg_dst: None,
            reg_src: Some(5),
            imm: None,
        };
        assert_eq!(instr.to_string(), "PUSH r5");
    }

    #[test]
    fn test_lift_pop_display() {
        let instr = GuestInstruction {
            opcode: GuestOpcode::Pop,
            reg_dst: Some(7),
            reg_src: None,
            imm: None,
        };
        assert_eq!(instr.to_string(), "POP r7");
    }

    #[test]
    fn test_lift_pop_unknown() {
        let instr = GuestInstruction {
            opcode: GuestOpcode::Pop,
            reg_dst: None,
            reg_src: None,
            imm: None,
        };
        assert_eq!(instr.to_string(), "POP ?");
    }

    #[test]
    fn test_error_sub_too_short() {
        assert_eq!(
            VmLifter::lift_to_instructions(&[0x02, 0x01]),
            Err("Unexpected end of bytecode for Sub instruction")
        );
    }

    #[test]
    fn test_error_push_reg_too_short() {
        assert_eq!(
            VmLifter::lift_to_instructions(&[0x03]),
            Err("Unexpected end of bytecode for Push reg instruction")
        );
    }

    #[test]
    fn test_error_pop_too_short() {
        assert_eq!(
            VmLifter::lift_to_instructions(&[0x04]),
            Err("Unexpected end of bytecode for Pop reg instruction")
        );
    }

    #[test]
    fn test_error_load_too_short() {
        assert_eq!(
            VmLifter::lift_to_instructions(&[0x05, 0x01, 0x02, 0x00]),
            Err("Unexpected end of bytecode for Load instruction")
        );
    }

    #[test]
    fn test_error_store_too_short() {
        assert_eq!(
            VmLifter::lift_to_instructions(&[0x06, 0x01, 0x02]),
            Err("Unexpected end of bytecode for Store instruction")
        );
    }

    #[test]
    fn test_error_loadimm_too_short() {
        assert_eq!(
            VmLifter::lift_to_instructions(&[0x08, 0x01, 0x00]),
            Err("Unexpected end of bytecode for LoadImm instruction")
        );
    }

    #[test]
    fn test_error_pushimm_too_short() {
        assert_eq!(
            VmLifter::lift_to_instructions(&[0x09, 0x00, 0x00]),
            Err("Unexpected end of bytecode for PushImm instruction")
        );
    }

    #[test]
    fn test_to_pseudo_il_empty() {
        let pseudo = VmLifter::to_pseudo_il(&[]);
        assert!(pseudo.is_empty());
    }

    #[test]
    fn test_run_pass_lifts_its_input() {
        // Was `run_pass();` — no input, result discarded, so it asserted only
        // that a hardcoded byte did not panic.
        assert!(run_pass(&[]).is_empty(), "no bytes means no pseudo-IL");
        let a = run_pass(&[0x07]);
        assert_eq!(a, run_pass(&[0x07]), "lifting must be deterministic");
    }

    #[test]
    fn test_guest_instruction_equality() {
        let a = GuestInstruction {
            opcode: GuestOpcode::Halt,
            reg_dst: None,
            reg_src: None,
            imm: None,
        };
        let b = a.clone();
        assert_eq!(a, b);
    }
}
