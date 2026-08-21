//! `handler_semantic_db` — Handler semantic database for virtual-machine analysis.
//!
//! Provides a curated catalogue of 80+ virtual handler patterns covering
//! stack operations, arithmetic, comparison, logical, shift, memory
//! read/write, and control-flow variants.  Handlers are matched against
//! disassembled code via [`HandlerMatcher`] using either exact or fuzzy
//! opcode-sequence matching, and results are stored in a [`SemanticMap`].

use crate::{BinOpKind, HandlerSemantic, PopDst, PushSrc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

// ---------------------------------------------------------------------------
// HandlerCategory
// ---------------------------------------------------------------------------

/// High-level category of a virtual handler.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum HandlerCategory {
    /// Push value onto the VM stack.
    Push,
    /// Pop value from the VM stack.
    Pop,
    /// Arithmetic operation.
    Alu,
    /// Memory read.
    MemRead,
    /// Memory write.
    MemWrite,
    /// Comparison / test.
    Compare,
    /// Bitwise logical.
    Logical,
    /// Bit shift / rotate.
    Shift,
    /// Unconditional or conditional jump.
    Branch,
    /// Call to subroutine.
    Call,
    /// Return from subroutine.
    Ret,
    /// No-operation / padding.
    Nop,
    /// Virtual instruction pointer manipulation.
    IpManip,
    /// Input/output (e.g. RDTSC, IN, OUT).
    IoOp,
    /// Unknown / unclassified.
    Unknown,
}

impl fmt::Display for HandlerCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Push => "PUSH",
            Self::Pop => "POP",
            Self::Alu => "ALU",
            Self::MemRead => "MEM_READ",
            Self::MemWrite => "MEM_WRITE",
            Self::Compare => "COMPARE",
            Self::Logical => "LOGICAL",
            Self::Shift => "SHIFT",
            Self::Branch => "BRANCH",
            Self::Call => "CALL",
            Self::Ret => "RET",
            Self::Nop => "NOP",
            Self::IpManip => "IP_MANIP",
            Self::IoOp => "IO_OP",
            Self::Unknown => "UNKNOWN",
        };
        write!(f, "{s}")
    }
}

// ---------------------------------------------------------------------------
// SemanticHandler
// ---------------------------------------------------------------------------

/// A complete semantic description of a virtual handler pattern.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SemanticHandler {
    /// Unique identifier for this handler pattern.
    pub id: u32,
    /// Short mnemonic (e.g. `"VPUSH_IMM64"`).
    pub opcode: String,
    /// Human-readable description.
    pub description: String,
    /// High-level semantic category.
    pub category: HandlerCategory,
    /// Structured semantic (same type used by the ISA synthesiser).
    pub semantic: HandlerSemantic,
    /// Operand-size in bytes (0 = no immediate operand).
    pub operand_size: u8,
    /// Byte sequence characteristic of this handler (prefix, not full body).
    pub byte_signature: Vec<u8>,
    /// Alternative byte signatures (or-matched).
    pub alt_signatures: Vec<Vec<u8>>,
    /// Tags for grouping (e.g. `["stack", "64bit"]`).
    pub tags: Vec<String>,
}

impl SemanticHandler {
    /// Create a handler with a single byte signature.
    #[must_use]
    pub fn new(
        id: u32,
        opcode: impl Into<String>,
        description: impl Into<String>,
        category: HandlerCategory,
        semantic: HandlerSemantic,
        operand_size: u8,
        byte_signature: Vec<u8>,
    ) -> Self {
        Self {
            id,
            opcode: opcode.into(),
            description: description.into(),
            category,
            semantic,
            operand_size,
            byte_signature,
            alt_signatures: Vec::new(),
            tags: Vec::new(),
        }
    }

    /// Add an alternative byte signature.
    #[must_use]
    pub fn with_alt(mut self, sig: Vec<u8>) -> Self {
        self.alt_signatures.push(sig);
        self
    }

    /// Add a tag.
    #[must_use]
    pub fn with_tag(mut self, tag: impl Into<String>) -> Self {
        self.tags.push(tag.into());
        self
    }

    /// Return `true` if `bytes` starts with the primary or any alternative
    /// byte signature.
    #[must_use]
    pub fn matches_bytes(&self, bytes: &[u8]) -> bool {
        self.starts_with(bytes, &self.byte_signature)
            || self
                .alt_signatures
                .iter()
                .any(|s| self.starts_with(bytes, s))
    }

    fn starts_with(&self, bytes: &[u8], sig: &[u8]) -> bool {
        if sig.is_empty() || bytes.len() < sig.len() {
            return false;
        }
        bytes.starts_with(sig)
    }
}

impl fmt::Display for SemanticHandler {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{:04}] {:20}  {}  ({})",
            self.id, self.opcode, self.description, self.category
        )
    }
}

// ---------------------------------------------------------------------------
// HandlerDb — the 80+ handler catalogue
// ---------------------------------------------------------------------------

/// Catalogue of known virtual handler patterns.
#[derive(Default)]
pub struct HandlerDb {
    handlers: Vec<SemanticHandler>,
}

impl HandlerDb {
    /// Create an empty database.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Build the full built-in handler catalogue with 80+ entries.
    #[must_use]
    pub fn builtin() -> Self {
        let mut db = Self::new();
        db.add_push_handlers();
        db.add_pop_handlers();
        db.add_alu_handlers();
        db.add_logical_handlers();
        db.add_shift_handlers();
        db.add_compare_handlers();
        db.add_mem_read_handlers();
        db.add_mem_write_handlers();
        db.add_branch_handlers();
        db.add_call_ret_handlers();
        db.add_nop_ip_handlers();
        db
    }

    /// Register a handler.
    pub fn register(&mut self, h: SemanticHandler) {
        self.handlers.push(h);
    }

    /// Return handler by id.
    #[must_use]
    pub fn by_id(&self, id: u32) -> Option<&SemanticHandler> {
        self.handlers.iter().find(|h| h.id == id)
    }

    /// Return all handlers in a category.
    #[must_use]
    pub fn by_category(&self, cat: HandlerCategory) -> Vec<&SemanticHandler> {
        self.handlers.iter().filter(|h| h.category == cat).collect()
    }

    /// Return all handlers with a specific tag.
    #[must_use]
    pub fn by_tag(&self, tag: &str) -> Vec<&SemanticHandler> {
        self.handlers
            .iter()
            .filter(|h| h.tags.iter().any(|t| t == tag))
            .collect()
    }

    /// Return all handlers whose opcode starts with `prefix`.
    #[must_use]
    pub fn by_opcode_prefix(&self, prefix: &str) -> Vec<&SemanticHandler> {
        self.handlers
            .iter()
            .filter(|h| h.opcode.starts_with(prefix))
            .collect()
    }

    /// Total handlers registered.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.handlers.len()
    }

    /// Return `true` if empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.handlers.is_empty()
    }

    // ── PUSH handlers (IDs 1–14) ──────────────────────────────────────────────

    fn add_push_handlers(&mut self) {
        // VPUSH_IMM8 — push sign-extended 8-bit immediate
        self.register(
            SemanticHandler::new(
                1,
                "VPUSH_IMM8",
                "Push sign-extended 8-bit immediate",
                HandlerCategory::Push,
                HandlerSemantic::Push(PushSrc::Constant(0)),
                1,
                vec![0x6A], // PUSH imm8
            )
            .with_tag("stack")
            .with_tag("imm"),
        );

        // VPUSH_IMM16
        self.register(
            SemanticHandler::new(
                2,
                "VPUSH_IMM16",
                "Push 16-bit immediate",
                HandlerCategory::Push,
                HandlerSemantic::Push(PushSrc::Constant(0)),
                2,
                vec![0x66, 0x68], // PUSH imm16
            )
            .with_tag("stack")
            .with_tag("imm"),
        );

        // VPUSH_IMM32
        self.register(
            SemanticHandler::new(
                3,
                "VPUSH_IMM32",
                "Push 32-bit immediate",
                HandlerCategory::Push,
                HandlerSemantic::Push(PushSrc::Constant(0)),
                4,
                vec![0x68], // PUSH imm32
            )
            .with_tag("stack")
            .with_tag("imm"),
        );

        // VPUSH_IMM64
        self.register(
            SemanticHandler::new(
                4,
                "VPUSH_IMM64",
                "Push 64-bit immediate (REX.W PUSH or MOV+PUSH)",
                HandlerCategory::Push,
                HandlerSemantic::Push(PushSrc::Constant(0)),
                8,
                vec![0x48, 0xB8], // MOVABS RAX, imm64 then PUSH RAX
            )
            .with_alt(vec![0x49, 0xB8]) // MOVABS R8, imm64
            .with_tag("stack")
            .with_tag("imm")
            .with_tag("64bit"),
        );

        // VPUSH_REG32 — push 32-bit register
        self.register(
            SemanticHandler::new(
                5,
                "VPUSH_REG32",
                "Push 32-bit virtual register",
                HandlerCategory::Push,
                HandlerSemantic::Push(PushSrc::VirtualReg(0)),
                1,
                vec![0x50], // PUSH EAX (representative)
            )
            .with_tag("stack")
            .with_tag("reg"),
        );

        // VPUSH_REG64
        self.register(
            SemanticHandler::new(
                6,
                "VPUSH_REG64",
                "Push 64-bit virtual register",
                HandlerCategory::Push,
                HandlerSemantic::Push(PushSrc::VirtualReg(0)),
                1,
                vec![0x50], // PUSH RAX (representative)
            )
            .with_alt(vec![0x41, 0x50]) // PUSH R8
            .with_tag("stack")
            .with_tag("reg")
            .with_tag("64bit"),
        );

        // VPUSH_MEM8 — push byte from memory
        self.register(
            SemanticHandler::new(
                7,
                "VPUSH_MEM8",
                "Push byte from memory address",
                HandlerCategory::Push,
                HandlerSemantic::Push(PushSrc::Memory),
                0,
                vec![0x8A, 0x00], // MOV AL, [EAX]
            )
            .with_tag("stack")
            .with_tag("mem"),
        );

        // VPUSH_MEM16
        self.register(
            SemanticHandler::new(
                8,
                "VPUSH_MEM16",
                "Push word from memory address",
                HandlerCategory::Push,
                HandlerSemantic::Push(PushSrc::Memory),
                0,
                vec![0x66, 0x8B, 0x00], // MOV AX, [EAX]
            )
            .with_tag("stack")
            .with_tag("mem"),
        );

        // VPUSH_MEM32
        self.register(
            SemanticHandler::new(
                9,
                "VPUSH_MEM32",
                "Push dword from memory address",
                HandlerCategory::Push,
                HandlerSemantic::Push(PushSrc::Memory),
                0,
                vec![0x8B, 0x00], // MOV EAX, [EAX]
            )
            .with_tag("stack")
            .with_tag("mem"),
        );

        // VPUSH_MEM64
        self.register(
            SemanticHandler::new(
                10,
                "VPUSH_MEM64",
                "Push qword from memory address",
                HandlerCategory::Push,
                HandlerSemantic::Push(PushSrc::Memory),
                0,
                vec![0x48, 0x8B, 0x00], // MOV RAX, [RAX]
            )
            .with_tag("stack")
            .with_tag("mem")
            .with_tag("64bit"),
        );

        // VPUSH_SP — push current stack pointer
        self.register(
            SemanticHandler::new(
                11,
                "VPUSH_SP",
                "Push current VM stack pointer",
                HandlerCategory::Push,
                HandlerSemantic::Push(PushSrc::VirtualReg(0xFF)),
                0,
                vec![0x54], // PUSH ESP
            )
            .with_tag("stack")
            .with_tag("sp"),
        );

        // VPUSH_FLAGS — push VM flags
        self.register(
            SemanticHandler::new(
                12,
                "VPUSH_FLAGS",
                "Push VM flags register",
                HandlerCategory::Push,
                HandlerSemantic::Push(PushSrc::VirtualReg(0xFE)),
                0,
                vec![0x9C], // PUSHFD
            )
            .with_tag("stack")
            .with_tag("flags"),
        );

        // VPUSH_ZERO — push constant zero
        self.register(
            SemanticHandler::new(
                13,
                "VPUSH_ZERO",
                "Push constant zero",
                HandlerCategory::Push,
                HandlerSemantic::Push(PushSrc::Constant(0)),
                0,
                vec![0x33, 0xC0, 0x50], // XOR EAX,EAX; PUSH EAX
            )
            .with_tag("stack")
            .with_tag("imm"),
        );

        // VPUSH_NEG1 — push -1 (all bits set)
        self.register(
            SemanticHandler::new(
                14,
                "VPUSH_NEG1",
                "Push constant -1 (all bits set)",
                HandlerCategory::Push,
                HandlerSemantic::Push(PushSrc::Constant(u64::MAX)),
                0,
                vec![0x6A, 0xFF], // PUSH -1
            )
            .with_tag("stack")
            .with_tag("imm"),
        );
    }

    // ── POP handlers (IDs 20–30) ──────────────────────────────────────────────

    fn add_pop_handlers(&mut self) {
        // VPOP_REG32
        self.register(
            SemanticHandler::new(
                20,
                "VPOP_REG32",
                "Pop into 32-bit virtual register",
                HandlerCategory::Pop,
                HandlerSemantic::Pop(PopDst::VirtualReg(0)),
                1,
                vec![0x58], // POP EAX
            )
            .with_tag("stack")
            .with_tag("reg"),
        );

        // VPOP_REG64
        self.register(
            SemanticHandler::new(
                21,
                "VPOP_REG64",
                "Pop into 64-bit virtual register",
                HandlerCategory::Pop,
                HandlerSemantic::Pop(PopDst::VirtualReg(0)),
                1,
                vec![0x58], // POP RAX
            )
            .with_alt(vec![0x41, 0x58]) // POP R8
            .with_tag("stack")
            .with_tag("reg")
            .with_tag("64bit"),
        );

        // VPOP_MEM8
        self.register(
            SemanticHandler::new(
                22,
                "VPOP_MEM8",
                "Pop byte to memory address",
                HandlerCategory::Pop,
                HandlerSemantic::Pop(PopDst::Memory),
                0,
                vec![0x88, 0x00], // MOV [EAX], AL
            )
            .with_tag("stack")
            .with_tag("mem"),
        );

        // VPOP_MEM16
        self.register(
            SemanticHandler::new(
                23,
                "VPOP_MEM16",
                "Pop word to memory address",
                HandlerCategory::Pop,
                HandlerSemantic::Pop(PopDst::Memory),
                0,
                vec![0x66, 0x89, 0x00], // MOV [EAX], AX
            )
            .with_tag("stack")
            .with_tag("mem"),
        );

        // VPOP_MEM32
        self.register(
            SemanticHandler::new(
                24,
                "VPOP_MEM32",
                "Pop dword to memory address",
                HandlerCategory::Pop,
                HandlerSemantic::Pop(PopDst::Memory),
                0,
                vec![0x89, 0x00], // MOV [EAX], EAX
            )
            .with_tag("stack")
            .with_tag("mem"),
        );

        // VPOP_MEM64
        self.register(
            SemanticHandler::new(
                25,
                "VPOP_MEM64",
                "Pop qword to memory address",
                HandlerCategory::Pop,
                HandlerSemantic::Pop(PopDst::Memory),
                0,
                vec![0x48, 0x89, 0x00], // MOV [RAX], RAX
            )
            .with_tag("stack")
            .with_tag("mem")
            .with_tag("64bit"),
        );

        // VPOP_DISCARD — pop and discard top of stack
        self.register(
            SemanticHandler::new(
                26,
                "VPOP_DISCARD",
                "Pop and discard top of stack",
                HandlerCategory::Pop,
                HandlerSemantic::Pop(PopDst::VirtualReg(0)),
                0,
                vec![0x83, 0xC4, 0x04], // ADD ESP, 4
            )
            .with_tag("stack"),
        );

        // VPOP_FLAGS
        self.register(
            SemanticHandler::new(
                27,
                "VPOP_FLAGS",
                "Pop into VM flags register",
                HandlerCategory::Pop,
                HandlerSemantic::Pop(PopDst::VirtualReg(0xFE)),
                0,
                vec![0x9D], // POPFD
            )
            .with_tag("stack")
            .with_tag("flags"),
        );

        // VPOP_SP
        self.register(
            SemanticHandler::new(
                28,
                "VPOP_SP",
                "Pop into VM stack pointer",
                HandlerCategory::Pop,
                HandlerSemantic::Pop(PopDst::VirtualReg(0xFF)),
                0,
                vec![0x5C], // POP ESP
            )
            .with_tag("stack")
            .with_tag("sp"),
        );

        // VDUP_TOP — duplicate top of stack
        self.register(
            SemanticHandler::new(
                29,
                "VDUP_TOP",
                "Duplicate the top of the VM stack",
                HandlerCategory::Push,
                HandlerSemantic::Push(PushSrc::VirtualReg(0)),
                0,
                vec![0x8B, 0x04, 0x24], // MOV EAX, [ESP]
            )
            .with_tag("stack"),
        );

        // VSWAP_TOP2 — swap top two stack items
        self.register(
            SemanticHandler::new(
                30,
                "VSWAP_TOP2",
                "Swap the top two VM stack items",
                HandlerCategory::Pop,
                HandlerSemantic::Unknown,
                0,
                vec![0x8B, 0x44, 0x24, 0x04], // MOV EAX, [ESP+4]
            )
            .with_tag("stack"),
        );
    }

    // ── ALU handlers (IDs 40–55) ──────────────────────────────────────────────

    fn add_alu_handlers(&mut self) {
        // VADD32
        self.register(
            SemanticHandler::new(
                40,
                "VADD32",
                "32-bit integer addition",
                HandlerCategory::Alu,
                HandlerSemantic::BinOp(BinOpKind::Add),
                0,
                vec![0x03, 0xC1], // ADD EAX, ECX
            )
            .with_tag("alu"),
        );

        // VADD64
        self.register(
            SemanticHandler::new(
                41,
                "VADD64",
                "64-bit integer addition",
                HandlerCategory::Alu,
                HandlerSemantic::BinOp(BinOpKind::Add),
                0,
                vec![0x48, 0x03, 0xC1], // ADD RAX, RCX
            )
            .with_tag("alu")
            .with_tag("64bit"),
        );

        // VSUB32
        self.register(
            SemanticHandler::new(
                42,
                "VSUB32",
                "32-bit integer subtraction",
                HandlerCategory::Alu,
                HandlerSemantic::BinOp(BinOpKind::Sub),
                0,
                vec![0x2B, 0xC1], // SUB EAX, ECX
            )
            .with_tag("alu"),
        );

        // VSUB64
        self.register(
            SemanticHandler::new(
                43,
                "VSUB64",
                "64-bit integer subtraction",
                HandlerCategory::Alu,
                HandlerSemantic::BinOp(BinOpKind::Sub),
                0,
                vec![0x48, 0x2B, 0xC1], // SUB RAX, RCX
            )
            .with_tag("alu")
            .with_tag("64bit"),
        );

        // VMUL32
        self.register(
            SemanticHandler::new(
                44,
                "VMUL32",
                "32-bit signed multiplication",
                HandlerCategory::Alu,
                HandlerSemantic::BinOp(BinOpKind::Mul),
                0,
                vec![0x0F, 0xAF, 0xC1], // IMUL EAX, ECX
            )
            .with_tag("alu"),
        );

        // VMUL64
        self.register(
            SemanticHandler::new(
                45,
                "VMUL64",
                "64-bit signed multiplication",
                HandlerCategory::Alu,
                HandlerSemantic::BinOp(BinOpKind::Mul),
                0,
                vec![0x48, 0x0F, 0xAF, 0xC1], // IMUL RAX, RCX
            )
            .with_tag("alu")
            .with_tag("64bit"),
        );

        // VDIV32
        self.register(
            SemanticHandler::new(
                46,
                "VDIV32",
                "32-bit unsigned division",
                HandlerCategory::Alu,
                HandlerSemantic::BinOp(BinOpKind::Div),
                0,
                vec![0xF7, 0xF1], // DIV ECX
            )
            .with_tag("alu"),
        );

        // VDIV64
        self.register(
            SemanticHandler::new(
                47,
                "VDIV64",
                "64-bit unsigned division",
                HandlerCategory::Alu,
                HandlerSemantic::BinOp(BinOpKind::Div),
                0,
                vec![0x48, 0xF7, 0xF1], // DIV RCX
            )
            .with_tag("alu")
            .with_tag("64bit"),
        );

        // VADD_IMM8
        self.register(
            SemanticHandler::new(
                48,
                "VADD_IMM8",
                "Add 8-bit sign-extended immediate",
                HandlerCategory::Alu,
                HandlerSemantic::BinOp(BinOpKind::Add),
                1,
                vec![0x83, 0xC0], // ADD EAX, imm8
            )
            .with_tag("alu")
            .with_tag("imm"),
        );

        // VADD_IMM32
        self.register(
            SemanticHandler::new(
                49,
                "VADD_IMM32",
                "Add 32-bit immediate",
                HandlerCategory::Alu,
                HandlerSemantic::BinOp(BinOpKind::Add),
                4,
                vec![0x05], // ADD EAX, imm32
            )
            .with_tag("alu")
            .with_tag("imm"),
        );

        // VSUB_IMM8
        self.register(
            SemanticHandler::new(
                50,
                "VSUB_IMM8",
                "Subtract 8-bit sign-extended immediate",
                HandlerCategory::Alu,
                HandlerSemantic::BinOp(BinOpKind::Sub),
                1,
                vec![0x83, 0xE8], // SUB EAX, imm8
            )
            .with_tag("alu")
            .with_tag("imm"),
        );

        // VINCR32
        self.register(
            SemanticHandler::new(
                51,
                "VINCR32",
                "Increment 32-bit top-of-stack",
                HandlerCategory::Alu,
                HandlerSemantic::BinOp(BinOpKind::Add),
                0,
                vec![0x40], // INC EAX
            )
            .with_tag("alu"),
        );

        // VDECR32
        self.register(
            SemanticHandler::new(
                52,
                "VDECR32",
                "Decrement 32-bit top-of-stack",
                HandlerCategory::Alu,
                HandlerSemantic::BinOp(BinOpKind::Sub),
                0,
                vec![0x48], // DEC EAX
            )
            .with_tag("alu"),
        );

        // VNEG32
        self.register(
            SemanticHandler::new(
                53,
                "VNEG32",
                "Negate (two's complement) 32-bit",
                HandlerCategory::Alu,
                HandlerSemantic::BinOp(BinOpKind::Sub),
                0,
                vec![0xF7, 0xD8], // NEG EAX
            )
            .with_tag("alu"),
        );

        // VNOT32 — bitwise NOT
        self.register(
            SemanticHandler::new(
                54,
                "VNOT32",
                "Bitwise NOT 32-bit",
                HandlerCategory::Logical,
                HandlerSemantic::BinOp(BinOpKind::Xor),
                0,
                vec![0xF7, 0xD0], // NOT EAX
            )
            .with_tag("logical"),
        );

        // VABS32 — absolute value (CDQE; XOR; SUB pattern)
        self.register(
            SemanticHandler::new(
                55,
                "VABS32",
                "Absolute value of signed 32-bit",
                HandlerCategory::Alu,
                HandlerSemantic::BinOp(BinOpKind::Sub),
                0,
                vec![0x99, 0x33, 0xC2], // CDQ; XOR EAX,EDX (abs via CDQ+XOR+SUB)
            )
            .with_tag("alu"),
        );
    }

    // ── Logical handlers (IDs 60–69) ──────────────────────────────────────────

    fn add_logical_handlers(&mut self) {
        // VAND32
        self.register(
            SemanticHandler::new(
                60,
                "VAND32",
                "Bitwise AND 32-bit",
                HandlerCategory::Logical,
                HandlerSemantic::BinOp(BinOpKind::And),
                0,
                vec![0x23, 0xC1], // AND EAX, ECX
            )
            .with_tag("logical"),
        );

        // VAND64
        self.register(
            SemanticHandler::new(
                61,
                "VAND64",
                "Bitwise AND 64-bit",
                HandlerCategory::Logical,
                HandlerSemantic::BinOp(BinOpKind::And),
                0,
                vec![0x48, 0x23, 0xC1], // AND RAX, RCX
            )
            .with_tag("logical")
            .with_tag("64bit"),
        );

        // VOR32
        self.register(
            SemanticHandler::new(
                62,
                "VOR32",
                "Bitwise OR 32-bit",
                HandlerCategory::Logical,
                HandlerSemantic::BinOp(BinOpKind::Or),
                0,
                vec![0x0B, 0xC1], // OR EAX, ECX
            )
            .with_tag("logical"),
        );

        // VOR64
        self.register(
            SemanticHandler::new(
                63,
                "VOR64",
                "Bitwise OR 64-bit",
                HandlerCategory::Logical,
                HandlerSemantic::BinOp(BinOpKind::Or),
                0,
                vec![0x48, 0x0B, 0xC1], // OR RAX, RCX
            )
            .with_tag("logical")
            .with_tag("64bit"),
        );

        // VXOR32
        self.register(
            SemanticHandler::new(
                64,
                "VXOR32",
                "Bitwise XOR 32-bit",
                HandlerCategory::Logical,
                HandlerSemantic::BinOp(BinOpKind::Xor),
                0,
                vec![0x33, 0xC1], // XOR EAX, ECX
            )
            .with_tag("logical"),
        );

        // VXOR64
        self.register(
            SemanticHandler::new(
                65,
                "VXOR64",
                "Bitwise XOR 64-bit",
                HandlerCategory::Logical,
                HandlerSemantic::BinOp(BinOpKind::Xor),
                0,
                vec![0x48, 0x33, 0xC1], // XOR RAX, RCX
            )
            .with_tag("logical")
            .with_tag("64bit"),
        );

        // VAND_IMM32
        self.register(
            SemanticHandler::new(
                66,
                "VAND_IMM32",
                "Bitwise AND with 32-bit immediate",
                HandlerCategory::Logical,
                HandlerSemantic::BinOp(BinOpKind::And),
                4,
                vec![0x25], // AND EAX, imm32
            )
            .with_tag("logical")
            .with_tag("imm"),
        );

        // VOR_IMM32
        self.register(
            SemanticHandler::new(
                67,
                "VOR_IMM32",
                "Bitwise OR with 32-bit immediate",
                HandlerCategory::Logical,
                HandlerSemantic::BinOp(BinOpKind::Or),
                4,
                vec![0x0D], // OR EAX, imm32
            )
            .with_tag("logical")
            .with_tag("imm"),
        );

        // VXOR_IMM32
        self.register(
            SemanticHandler::new(
                68,
                "VXOR_IMM32",
                "Bitwise XOR with 32-bit immediate",
                HandlerCategory::Logical,
                HandlerSemantic::BinOp(BinOpKind::Xor),
                4,
                vec![0x35], // XOR EAX, imm32
            )
            .with_tag("logical")
            .with_tag("imm"),
        );

        // VTEST32 — test bits
        self.register(
            SemanticHandler::new(
                69,
                "VTEST32",
                "Test bits (AND without storing result)",
                HandlerCategory::Compare,
                HandlerSemantic::Cmp,
                0,
                vec![0x85, 0xC0], // TEST EAX, EAX
            )
            .with_tag("compare"),
        );
    }

    // ── Shift/rotate handlers (IDs 70–78) ────────────────────────────────────

    fn add_shift_handlers(&mut self) {
        // VSHL32
        self.register(
            SemanticHandler::new(
                70,
                "VSHL32",
                "Logical shift left 32-bit by CL",
                HandlerCategory::Shift,
                HandlerSemantic::BinOp(BinOpKind::Shl),
                0,
                vec![0xD3, 0xE0], // SHL EAX, CL
            )
            .with_tag("shift"),
        );

        // VSHR32
        self.register(
            SemanticHandler::new(
                71,
                "VSHR32",
                "Logical shift right 32-bit by CL",
                HandlerCategory::Shift,
                HandlerSemantic::BinOp(BinOpKind::Shr),
                0,
                vec![0xD3, 0xE8], // SHR EAX, CL
            )
            .with_tag("shift"),
        );

        // VSAR32
        self.register(
            SemanticHandler::new(
                72,
                "VSAR32",
                "Arithmetic shift right 32-bit by CL",
                HandlerCategory::Shift,
                HandlerSemantic::BinOp(BinOpKind::Sar),
                0,
                vec![0xD3, 0xF8], // SAR EAX, CL
            )
            .with_tag("shift"),
        );

        // VROL32
        self.register(
            SemanticHandler::new(
                73,
                "VROL32",
                "Rotate left 32-bit by CL",
                HandlerCategory::Shift,
                HandlerSemantic::BinOp(BinOpKind::Rol),
                0,
                vec![0xD3, 0xC0], // ROL EAX, CL
            )
            .with_tag("shift"),
        );

        // VROR32
        self.register(
            SemanticHandler::new(
                74,
                "VROR32",
                "Rotate right 32-bit by CL",
                HandlerCategory::Shift,
                HandlerSemantic::BinOp(BinOpKind::Ror),
                0,
                vec![0xD3, 0xC8], // ROR EAX, CL
            )
            .with_tag("shift"),
        );

        // VSHL32_IMM8
        self.register(
            SemanticHandler::new(
                75,
                "VSHL32_IMM8",
                "Logical shift left 32-bit by immediate",
                HandlerCategory::Shift,
                HandlerSemantic::BinOp(BinOpKind::Shl),
                1,
                vec![0xC1, 0xE0], // SHL EAX, imm8
            )
            .with_tag("shift")
            .with_tag("imm"),
        );

        // VSHR32_IMM8
        self.register(
            SemanticHandler::new(
                76,
                "VSHR32_IMM8",
                "Logical shift right 32-bit by immediate",
                HandlerCategory::Shift,
                HandlerSemantic::BinOp(BinOpKind::Shr),
                1,
                vec![0xC1, 0xE8], // SHR EAX, imm8
            )
            .with_tag("shift")
            .with_tag("imm"),
        );

        // VSAR64
        self.register(
            SemanticHandler::new(
                77,
                "VSAR64",
                "Arithmetic shift right 64-bit by CL",
                HandlerCategory::Shift,
                HandlerSemantic::BinOp(BinOpKind::Sar),
                0,
                vec![0x48, 0xD3, 0xF8], // SAR RAX, CL
            )
            .with_tag("shift")
            .with_tag("64bit"),
        );

        // VBSWAP32
        self.register(
            SemanticHandler::new(
                78,
                "VBSWAP32",
                "Byte-swap 32-bit register",
                HandlerCategory::Shift,
                HandlerSemantic::BinOp(BinOpKind::Rol),
                0,
                vec![0x0F, 0xC8], // BSWAP EAX
            )
            .with_tag("shift"),
        );
    }

    // ── Compare handlers (IDs 80–86) ──────────────────────────────────────────

    fn add_compare_handlers(&mut self) {
        // VCMP32
        self.register(
            SemanticHandler::new(
                80,
                "VCMP32",
                "Compare two 32-bit values (SUB without store)",
                HandlerCategory::Compare,
                HandlerSemantic::Cmp,
                0,
                vec![0x3B, 0xC1], // CMP EAX, ECX
            )
            .with_tag("compare"),
        );

        // VCMP64
        self.register(
            SemanticHandler::new(
                81,
                "VCMP64",
                "Compare two 64-bit values",
                HandlerCategory::Compare,
                HandlerSemantic::Cmp,
                0,
                vec![0x48, 0x3B, 0xC1], // CMP RAX, RCX
            )
            .with_tag("compare")
            .with_tag("64bit"),
        );

        // VCMP_ZERO32
        self.register(
            SemanticHandler::new(
                82,
                "VCMP_ZERO32",
                "Compare 32-bit value to zero",
                HandlerCategory::Compare,
                HandlerSemantic::Cmp,
                0,
                vec![0x85, 0xC0], // TEST EAX, EAX
            )
            .with_tag("compare"),
        );

        // VCMP_IMM8
        self.register(
            SemanticHandler::new(
                83,
                "VCMP_IMM8",
                "Compare 32-bit value to 8-bit immediate",
                HandlerCategory::Compare,
                HandlerSemantic::Cmp,
                1,
                vec![0x83, 0xF8], // CMP EAX, imm8
            )
            .with_tag("compare")
            .with_tag("imm"),
        );

        // VCMP_IMM32
        self.register(
            SemanticHandler::new(
                84,
                "VCMP_IMM32",
                "Compare 32-bit value to 32-bit immediate",
                HandlerCategory::Compare,
                HandlerSemantic::Cmp,
                4,
                vec![0x3D], // CMP EAX, imm32
            )
            .with_tag("compare")
            .with_tag("imm"),
        );

        // VSETE — set if equal (SETE AL)
        self.register(
            SemanticHandler::new(
                85,
                "VSETE",
                "Set byte if equal (ZF==1)",
                HandlerCategory::Compare,
                HandlerSemantic::Cmp,
                0,
                vec![0x0F, 0x94, 0xC0], // SETE AL
            )
            .with_tag("compare")
            .with_tag("setcc"),
        );

        // VSETL — set if less (SETL AL)
        self.register(
            SemanticHandler::new(
                86,
                "VSETL",
                "Set byte if less than (signed, SF≠OF)",
                HandlerCategory::Compare,
                HandlerSemantic::Cmp,
                0,
                vec![0x0F, 0x9C, 0xC0], // SETL AL
            )
            .with_tag("compare")
            .with_tag("setcc"),
        );
    }

    // ── Memory read/write handlers (IDs 90–101) ───────────────────────────────

    fn add_mem_read_handlers(&mut self) {
        // VLOAD8
        self.register(
            SemanticHandler::new(
                90,
                "VLOAD8",
                "Load byte from memory",
                HandlerCategory::MemRead,
                HandlerSemantic::Load(1),
                0,
                vec![0x8A, 0x00], // MOV AL, [EAX]
            )
            .with_tag("mem")
            .with_tag("load"),
        );

        // VLOAD16
        self.register(
            SemanticHandler::new(
                91,
                "VLOAD16",
                "Load word from memory",
                HandlerCategory::MemRead,
                HandlerSemantic::Load(2),
                0,
                vec![0x66, 0x8B, 0x00], // MOV AX, [EAX]
            )
            .with_tag("mem")
            .with_tag("load"),
        );

        // VLOAD32
        self.register(
            SemanticHandler::new(
                92,
                "VLOAD32",
                "Load dword from memory",
                HandlerCategory::MemRead,
                HandlerSemantic::Load(4),
                0,
                vec![0x8B, 0x00], // MOV EAX, [EAX]
            )
            .with_tag("mem")
            .with_tag("load"),
        );

        // VLOAD64
        self.register(
            SemanticHandler::new(
                93,
                "VLOAD64",
                "Load qword from memory",
                HandlerCategory::MemRead,
                HandlerSemantic::Load(8),
                0,
                vec![0x48, 0x8B, 0x00], // MOV RAX, [RAX]
            )
            .with_tag("mem")
            .with_tag("load")
            .with_tag("64bit"),
        );

        // VLOAD8_DISP — load byte with displacement
        self.register(
            SemanticHandler::new(
                94,
                "VLOAD8_DISP",
                "Load byte from [base + displacement]",
                HandlerCategory::MemRead,
                HandlerSemantic::Load(1),
                1,
                vec![0x8A, 0x40], // MOV AL, [EAX+disp8]
            )
            .with_tag("mem")
            .with_tag("load"),
        );

        // VLOAD32_DISP
        self.register(
            SemanticHandler::new(
                95,
                "VLOAD32_DISP",
                "Load dword from [base + displacement]",
                HandlerCategory::MemRead,
                HandlerSemantic::Load(4),
                1,
                vec![0x8B, 0x40], // MOV EAX, [EAX+disp8]
            )
            .with_tag("mem")
            .with_tag("load"),
        );
    }

    fn add_mem_write_handlers(&mut self) {
        // VSTORE8
        self.register(
            SemanticHandler::new(
                96,
                "VSTORE8",
                "Store byte to memory",
                HandlerCategory::MemWrite,
                HandlerSemantic::Store(1),
                0,
                vec![0x88, 0x00], // MOV [EAX], AL
            )
            .with_tag("mem")
            .with_tag("store"),
        );

        // VSTORE16
        self.register(
            SemanticHandler::new(
                97,
                "VSTORE16",
                "Store word to memory",
                HandlerCategory::MemWrite,
                HandlerSemantic::Store(2),
                0,
                vec![0x66, 0x89, 0x00], // MOV [EAX], AX
            )
            .with_tag("mem")
            .with_tag("store"),
        );

        // VSTORE32
        self.register(
            SemanticHandler::new(
                98,
                "VSTORE32",
                "Store dword to memory",
                HandlerCategory::MemWrite,
                HandlerSemantic::Store(4),
                0,
                vec![0x89, 0x00], // MOV [EAX], EAX
            )
            .with_tag("mem")
            .with_tag("store"),
        );

        // VSTORE64
        self.register(
            SemanticHandler::new(
                99,
                "VSTORE64",
                "Store qword to memory",
                HandlerCategory::MemWrite,
                HandlerSemantic::Store(8),
                0,
                vec![0x48, 0x89, 0x00], // MOV [RAX], RAX
            )
            .with_tag("mem")
            .with_tag("store")
            .with_tag("64bit"),
        );

        // VSTORE8_DISP
        self.register(
            SemanticHandler::new(
                100,
                "VSTORE8_DISP",
                "Store byte to [base + displacement]",
                HandlerCategory::MemWrite,
                HandlerSemantic::Store(1),
                1,
                vec![0x88, 0x40], // MOV [EAX+disp8], AL
            )
            .with_tag("mem")
            .with_tag("store"),
        );

        // VSTORE32_DISP
        self.register(
            SemanticHandler::new(
                101,
                "VSTORE32_DISP",
                "Store dword to [base + displacement]",
                HandlerCategory::MemWrite,
                HandlerSemantic::Store(4),
                1,
                vec![0x89, 0x40], // MOV [EAX+disp8], EAX
            )
            .with_tag("mem")
            .with_tag("store"),
        );
    }

    // ── Branch/call/ret handlers (IDs 110–119) ────────────────────────────────

    fn add_branch_handlers(&mut self) {
        // VJMP_ABS — absolute indirect jump
        self.register(
            SemanticHandler::new(
                110,
                "VJMP_ABS",
                "Unconditional jump to absolute address",
                HandlerCategory::Branch,
                HandlerSemantic::Branch,
                0,
                vec![0xFF, 0xE0], // JMP RAX
            )
            .with_tag("branch"),
        );

        // VJMP_REL32
        self.register(
            SemanticHandler::new(
                111,
                "VJMP_REL32",
                "Relative jump by 32-bit signed offset",
                HandlerCategory::Branch,
                HandlerSemantic::Branch,
                4,
                vec![0xE9], // JMP rel32
            )
            .with_tag("branch")
            .with_tag("rel"),
        );

        // VJMP_REL8
        self.register(
            SemanticHandler::new(
                112,
                "VJMP_REL8",
                "Relative jump by 8-bit signed offset",
                HandlerCategory::Branch,
                HandlerSemantic::Branch,
                1,
                vec![0xEB], // JMP rel8
            )
            .with_tag("branch")
            .with_tag("rel"),
        );

        // VJZ — jump if zero
        self.register(
            SemanticHandler::new(
                113,
                "VJZ",
                "Jump if zero (ZF=1)",
                HandlerCategory::Branch,
                HandlerSemantic::Branch,
                4,
                vec![0x0F, 0x84], // JZ rel32
            )
            .with_tag("branch")
            .with_tag("cond"),
        );

        // VJNZ — jump if not zero
        self.register(
            SemanticHandler::new(
                114,
                "VJNZ",
                "Jump if not zero (ZF=0)",
                HandlerCategory::Branch,
                HandlerSemantic::Branch,
                4,
                vec![0x0F, 0x85], // JNZ rel32
            )
            .with_tag("branch")
            .with_tag("cond"),
        );

        // VJL — jump if less (signed)
        self.register(
            SemanticHandler::new(
                115,
                "VJLT",
                "Jump if less than (signed, SF≠OF)",
                HandlerCategory::Branch,
                HandlerSemantic::Branch,
                4,
                vec![0x0F, 0x8C], // JL rel32
            )
            .with_tag("branch")
            .with_tag("cond"),
        );

        // VJGE — jump if greater or equal
        self.register(
            SemanticHandler::new(
                116,
                "VJGE",
                "Jump if greater or equal (signed, SF=OF)",
                HandlerCategory::Branch,
                HandlerSemantic::Branch,
                4,
                vec![0x0F, 0x8D], // JGE rel32
            )
            .with_tag("branch")
            .with_tag("cond"),
        );
    }

    fn add_call_ret_handlers(&mut self) {
        // VCALL_ABS — call through register
        self.register(
            SemanticHandler::new(
                117,
                "VCALL_ABS",
                "Call absolute address in register",
                HandlerCategory::Call,
                HandlerSemantic::Call,
                0,
                vec![0xFF, 0xD0], // CALL RAX
            )
            .with_tag("call"),
        );

        // VCALL_REL32
        self.register(
            SemanticHandler::new(
                118,
                "VCALL_REL32",
                "Near call by 32-bit relative offset",
                HandlerCategory::Call,
                HandlerSemantic::Call,
                4,
                vec![0xE8], // CALL rel32
            )
            .with_tag("call")
            .with_tag("rel"),
        );

        // VRET
        self.register(
            SemanticHandler::new(
                119,
                "VRET",
                "Return from VM subroutine",
                HandlerCategory::Ret,
                HandlerSemantic::Ret,
                0,
                vec![0xC3], // RET
            )
            .with_tag("ret"),
        );
    }

    fn add_nop_ip_handlers(&mut self) {
        // VNOP
        self.register(
            SemanticHandler::new(
                120,
                "VNOP",
                "No-operation (advance IP by 1)",
                HandlerCategory::Nop,
                HandlerSemantic::IpAdvance(1),
                0,
                vec![0x90], // NOP
            )
            .with_tag("nop"),
        );

        // VNOP_MULTI — multi-byte NOP
        self.register(
            SemanticHandler::new(
                121,
                "VNOP2",
                "Two-byte no-operation",
                HandlerCategory::Nop,
                HandlerSemantic::IpAdvance(2),
                0,
                vec![0x66, 0x90], // NOP (two-byte)
            )
            .with_tag("nop"),
        );

        // VIP_INC — advance virtual IP by 1
        self.register(
            SemanticHandler::new(
                122,
                "VIP_INC",
                "Advance virtual instruction pointer by 1",
                HandlerCategory::IpManip,
                HandlerSemantic::IpAdvance(1),
                0,
                vec![0xFF, 0xC6], // INC ESI (ESI often used as virtual IP)
            )
            .with_tag("ip"),
        );

        // VIP_ADVANCE4 — advance virtual IP by 4
        self.register(
            SemanticHandler::new(
                123,
                "VIP_ADVANCE4",
                "Advance virtual instruction pointer by 4",
                HandlerCategory::IpManip,
                HandlerSemantic::IpAdvance(4),
                0,
                vec![0x83, 0xC6, 0x04], // ADD ESI, 4
            )
            .with_tag("ip"),
        );

        // VRDTSC — read time stamp counter
        self.register(
            SemanticHandler::new(
                124,
                "VRDTSC",
                "Read timestamp counter (RDTSC)",
                HandlerCategory::IoOp,
                HandlerSemantic::Unknown,
                0,
                vec![0x0F, 0x31], // RDTSC
            )
            .with_tag("io"),
        );
    }
}

// ---------------------------------------------------------------------------
// MatchMode
// ---------------------------------------------------------------------------

/// Whether to use exact or fuzzy byte-signature matching.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchMode {
    /// Require an exact byte prefix match.
    Exact,
    /// Allow a Hamming-distance-1 mismatch in the signature bytes.
    Fuzzy,
}

// ---------------------------------------------------------------------------
// HandlerMatcher
// ---------------------------------------------------------------------------

/// Matches raw handler bytes against the [`HandlerDb`] catalogue.
pub struct HandlerMatcher<'db> {
    db: &'db HandlerDb,
}

impl<'db> HandlerMatcher<'db> {
    /// Create a matcher for the given database.
    #[must_use]
    pub const fn new(db: &'db HandlerDb) -> Self {
        Self { db }
    }

    /// Find all catalogue entries whose byte signature matches `bytes` in
    /// the given `mode`.
    #[must_use]
    pub fn find(&self, bytes: &[u8], mode: MatchMode) -> Vec<&SemanticHandler> {
        self.db
            .handlers
            .iter()
            .filter(|h| match mode {
                MatchMode::Exact => h.matches_bytes(bytes),
                MatchMode::Fuzzy => self.fuzzy_match(h, bytes),
            })
            .collect()
    }

    /// Return the best (lowest operand-size, highest confidence) single match.
    #[must_use]
    pub fn best_match(&self, bytes: &[u8], mode: MatchMode) -> Option<&SemanticHandler> {
        let mut candidates = self.find(bytes, mode);
        // Prefer exact primary signature matches over alt-signature matches.
        // Among equals, prefer shorter signature (more specific).
        candidates.sort_by_key(|h| h.byte_signature.len());
        candidates.into_iter().next()
    }

    /// Fuzzy matching: allow up to 1 byte difference in the signature prefix.
    fn fuzzy_match(&self, handler: &SemanticHandler, bytes: &[u8]) -> bool {
        Self::hamming_distance_le1(bytes, &handler.byte_signature)
            || handler
                .alt_signatures
                .iter()
                .any(|s| Self::hamming_distance_le1(bytes, s))
    }

    fn hamming_distance_le1(bytes: &[u8], sig: &[u8]) -> bool {
        if sig.is_empty() || bytes.len() < sig.len() {
            return false;
        }
        let mismatches = bytes[..sig.len()]
            .iter()
            .zip(sig.iter())
            .filter(|(a, b)| a != b)
            .count();
        mismatches <= 1
    }
}

// ---------------------------------------------------------------------------
// SemanticMap
// ---------------------------------------------------------------------------

/// Maps handler virtual addresses to their resolved [`HandlerSemantic`]s.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct SemanticMap {
    /// `handler_address → (handler_id, semantic)`.
    entries: HashMap<u64, (u32, HandlerSemantic)>,
}

impl SemanticMap {
    /// Create an empty map.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Associate `address` with the given handler.
    pub fn insert(&mut self, address: u64, handler_id: u32, semantic: HandlerSemantic) {
        self.entries.insert(address, (handler_id, semantic));
    }

    /// Look up the semantic for `address`.
    #[must_use]
    pub fn get(&self, address: u64) -> Option<&HandlerSemantic> {
        self.entries.get(&address).map(|(_, s)| s)
    }

    /// Look up the handler id for `address`.
    #[must_use]
    pub fn handler_id(&self, address: u64) -> Option<u32> {
        self.entries.get(&address).map(|(id, _)| *id)
    }

    /// Return all mapped addresses sorted ascending.
    #[must_use]
    pub fn addresses(&self) -> Vec<u64> {
        let mut v: Vec<u64> = self.entries.keys().copied().collect();
        v.sort_unstable();
        v
    }

    /// Count mapped entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Return `true` if empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Remove an entry.
    pub fn remove(&mut self, address: u64) {
        self.entries.remove(&address);
    }

    /// Merge another map into this one (callee wins on conflict).
    pub fn merge(&mut self, other: Self) {
        self.entries.extend(other.entries);
    }

    /// Return all entries grouped by [`HandlerCategory`] (via the handler
    /// semantic).
    #[must_use]
    pub fn by_semantic_kind(&self) -> HashMap<String, Vec<u64>> {
        let mut map: HashMap<String, Vec<u64>> = HashMap::new();
        for (addr, (_, sem)) in &self.entries {
            let key = match sem {
                HandlerSemantic::Push(_) => "PUSH",
                HandlerSemantic::Pop(_) => "POP",
                HandlerSemantic::BinOp(_) => "BINOP",
                HandlerSemantic::Load(_) => "LOAD",
                HandlerSemantic::Store(_) => "STORE",
                HandlerSemantic::Cmp => "CMP",
                HandlerSemantic::Branch => "BRANCH",
                HandlerSemantic::Call => "CALL",
                HandlerSemantic::Ret => "RET",
                HandlerSemantic::IpAdvance(_) => "IP",
                HandlerSemantic::Halt => "HALT",
                HandlerSemantic::Unknown => "UNKNOWN",
            };
            map.entry(key.to_string()).or_default().push(*addr);
        }
        map
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ── HandlerDb ─────────────────────────────────────────────────────────────

    #[test]
    fn builtin_db_has_at_least_80_handlers() {
        let db = HandlerDb::builtin();
        assert!(
            db.len() >= 80,
            "expected ≥ 80 built-in handlers, got {}",
            db.len()
        );
    }

    #[test]
    fn db_has_push_handlers() {
        let db = HandlerDb::builtin();
        let pushes = db.by_category(HandlerCategory::Push);
        assert!(!pushes.is_empty());
    }

    #[test]
    fn db_has_pop_handlers() {
        let db = HandlerDb::builtin();
        assert!(!db.by_category(HandlerCategory::Pop).is_empty());
    }

    #[test]
    fn db_has_alu_handlers() {
        let db = HandlerDb::builtin();
        assert!(!db.by_category(HandlerCategory::Alu).is_empty());
    }

    #[test]
    fn db_has_mem_read_handlers() {
        let db = HandlerDb::builtin();
        assert!(!db.by_category(HandlerCategory::MemRead).is_empty());
    }

    #[test]
    fn db_has_mem_write_handlers() {
        let db = HandlerDb::builtin();
        assert!(!db.by_category(HandlerCategory::MemWrite).is_empty());
    }

    #[test]
    fn db_has_branch_handlers() {
        let db = HandlerDb::builtin();
        assert!(!db.by_category(HandlerCategory::Branch).is_empty());
    }

    #[test]
    fn db_by_id_returns_correct_handler() {
        let db = HandlerDb::builtin();
        let h = db.by_id(1).unwrap();
        assert_eq!(h.id, 1);
        assert_eq!(h.opcode, "VPUSH_IMM8");
    }

    #[test]
    fn db_by_tag_stack_non_empty() {
        let db = HandlerDb::builtin();
        let tagged = db.by_tag("stack");
        assert!(!tagged.is_empty());
    }

    #[test]
    fn db_by_opcode_prefix_vpush() {
        let db = HandlerDb::builtin();
        let results = db.by_opcode_prefix("VPUSH");
        assert!(!results.is_empty());
        assert!(results.iter().all(|h| h.opcode.starts_with("VPUSH")));
    }

    // ── SemanticHandler ───────────────────────────────────────────────────────

    #[test]
    fn handler_matches_exact_bytes() {
        let db = HandlerDb::builtin();
        let h = db.by_id(40).unwrap(); // VADD32 = 03 C1
        assert!(h.matches_bytes(&[0x03, 0xC1, 0x90]));
    }

    #[test]
    fn handler_does_not_match_wrong_bytes() {
        let db = HandlerDb::builtin();
        let h = db.by_id(40).unwrap(); // VADD32
        assert!(!h.matches_bytes(&[0xAA, 0xBB]));
    }

    #[test]
    fn handler_matches_alt_signature() {
        let db = HandlerDb::builtin();
        // VPUSH_IMM64 has alt sig 49 B8
        let h = db.by_id(4).unwrap();
        assert!(h.matches_bytes(&[0x49, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]));
    }

    #[test]
    fn handler_display_contains_opcode() {
        let db = HandlerDb::builtin();
        let s = db.by_id(92).unwrap().to_string();
        assert!(s.contains("VLOAD32"));
    }

    // ── HandlerMatcher ────────────────────────────────────────────────────────

    #[test]
    fn matcher_exact_finds_vadd32() {
        let db = HandlerDb::builtin();
        let matcher = HandlerMatcher::new(&db);
        let code = [0x03u8, 0xC1, 0x90, 0xC3];
        let results = matcher.find(&code, MatchMode::Exact);
        assert!(results.iter().any(|h| h.id == 40));
    }

    #[test]
    fn matcher_exact_no_match() {
        let db = HandlerDb::builtin();
        let matcher = HandlerMatcher::new(&db);
        let code = [0xFFu8, 0xFF, 0xFF];
        assert!(matcher.find(&code, MatchMode::Exact).is_empty());
    }

    #[test]
    fn matcher_fuzzy_allows_one_mismatch() {
        let db = HandlerDb::builtin();
        let matcher = HandlerMatcher::new(&db);
        // VADD32 = [0x03, 0xC1]; mutate one byte
        let code = [0x03u8, 0xC0, 0x90]; // second byte differs
        let results = matcher.find(&code, MatchMode::Fuzzy);
        assert!(
            results
                .iter()
                .any(|h| h.id == 40 || h.category == HandlerCategory::Alu)
        );
    }

    #[test]
    fn matcher_best_match_returns_some_for_known_sequence() {
        let db = HandlerDb::builtin();
        let matcher = HandlerMatcher::new(&db);
        let code = [0x9Cu8, 0x60]; // PUSHFD + PUSHAD (VPUSH_FLAGS)
        let result = matcher.best_match(&code, MatchMode::Exact);
        assert!(result.is_some());
    }

    // ── SemanticMap ───────────────────────────────────────────────────────────

    #[test]
    fn semantic_map_insert_and_get() {
        let mut map = SemanticMap::new();
        map.insert(0x1000, 40, HandlerSemantic::BinOp(BinOpKind::Add));
        let sem = map.get(0x1000).unwrap();
        assert!(matches!(sem, HandlerSemantic::BinOp(BinOpKind::Add)));
    }

    #[test]
    fn semantic_map_handler_id() {
        let mut map = SemanticMap::new();
        map.insert(0x2000, 92, HandlerSemantic::Load(4));
        assert_eq!(map.handler_id(0x2000), Some(92));
    }

    #[test]
    fn semantic_map_get_unknown_returns_none() {
        let map = SemanticMap::new();
        assert!(map.get(0xDEAD).is_none());
    }

    #[test]
    fn semantic_map_addresses_sorted() {
        let mut map = SemanticMap::new();
        map.insert(0x3000, 1, HandlerSemantic::Push(PushSrc::Constant(0)));
        map.insert(0x1000, 2, HandlerSemantic::Pop(PopDst::VirtualReg(0)));
        map.insert(0x2000, 3, HandlerSemantic::Ret);
        let addrs = map.addresses();
        assert_eq!(addrs, vec![0x1000, 0x2000, 0x3000]);
    }

    #[test]
    fn semantic_map_merge() {
        let mut a = SemanticMap::new();
        a.insert(0x100, 1, HandlerSemantic::Ret);

        let mut b = SemanticMap::new();
        b.insert(0x200, 2, HandlerSemantic::Call);

        a.merge(b);
        assert_eq!(a.len(), 2);
    }

    #[test]
    fn semantic_map_by_semantic_kind() {
        let mut map = SemanticMap::new();
        map.insert(0x1000, 1, HandlerSemantic::Push(PushSrc::Constant(0)));
        map.insert(0x2000, 2, HandlerSemantic::Push(PushSrc::VirtualReg(0)));
        map.insert(0x3000, 3, HandlerSemantic::Ret);
        let kinds = map.by_semantic_kind();
        assert_eq!(kinds["PUSH"].len(), 2);
        assert_eq!(kinds["RET"].len(), 1);
    }

    #[test]
    fn semantic_map_remove() {
        let mut map = SemanticMap::new();
        map.insert(0x1000, 1, HandlerSemantic::Ret);
        map.remove(0x1000);
        assert!(map.is_empty());
    }

    // ── HandlerCategory ───────────────────────────────────────────────────────

    #[test]
    fn handler_category_display() {
        assert_eq!(HandlerCategory::Alu.to_string(), "ALU");
        assert_eq!(HandlerCategory::MemRead.to_string(), "MEM_READ");
    }
}
