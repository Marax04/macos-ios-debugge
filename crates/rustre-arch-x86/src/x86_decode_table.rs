//! Complete x86-64 opcode decode lookup table.
//!
//! Provides:
//! - [`X86DecodeTable`] — the main lookup table engine
//! - [`OpcodeEntry`] — a single opcode descriptor
//! - [`OpcodeGroup`] — /digit group extensions
//! - [`InstrFormat`] — operand encoding format
//! - [`PrefixHandler`] — mandatory/REX/VEX prefix semantics
//! - [`Escape0F`] — two-byte 0F xx opcode space
//! - [`Escape0F38`] — three-byte 0F 38 xx opcode space
//! - [`Escape0F3A`] — three-byte 0F 3A xx opcode space
//!
//! # Layer distinction
//!
//! This module is the **runtime decode engine**: tables are built on first use
//! into `Vec<OpcodeEntry>` and carry rich per-entry metadata (description
//! strings, privilege and fault flags, group extensions for `/digit` opcodes,
//! and separate sub-tables for 0F / 0F-38 / 0F-3A escape bytes).
//!
//! It intentionally covers the same opcode space as [`crate::tables`], which
//! provides the *static, zero-heap* arrays used by the lightweight disassembler
//! length computation and by `crate::sse` for SSE descriptor metadata.  Neither
//! module replaces the other.
//!
//! # Dispatch status (NOT wired into `src/lift.rs`)
//!
//! This module is **not** part of the active lifting path. `src/lift.rs`
//! dispatches every mnemonic directly via its own native match arms (added
//! across several hardening passes), and does not call into this module.
//! It is intentionally retained -- not dead code pending removal -- per
//! explicit user instruction, as a possible future cross-validation /
//! second-opinion decode path independent of `lift.rs`.

// ---------------------------------------------------------------------------
// InstrFormat — operand encoding descriptors
// ---------------------------------------------------------------------------

/// x86-64 instruction operand format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum InstrFormat {
    /// No operands (e.g. NOP, RET, HLT).
    ZO,
    /// Single implicit operand (e.g. PUSH rAX).
    O,
    /// reg/mem8 only (no explicit reg field).
    M1,
    /// r/m, reg  (`ModRM`, both operands).
    MR,
    /// reg, r/m  (`ModRM` reversed).
    RM,
    /// reg, r/m, imm8.
    RMI8,
    /// reg, r/m, imm16.
    RMI16,
    /// reg, r/m, imm32.
    RMI32,
    /// r/m, imm8.
    MI8,
    /// r/m, imm16.
    MI16,
    /// r/m, imm32.
    MI32,
    /// Opcode + register (no `ModRM`, e.g. INC rAX).
    OI,
    /// rel8 (short branch target).
    D8,
    /// rel16/32 (near branch target).
    D32,
    /// r/m (single r/m operand, unary).
    M,
    /// r/m, CL (shift by CL).
    MC,
    /// r/m, 1  (shift by 1).
    M1S,
    /// reg, r/m, imm8 (3-operand).
    RVMR,
    /// VEX.NDS: reg, reg, r/m (AVX 3-operand, no imm).
    RVM,
    /// Implicit accumulator + imm.
    I8,
    /// imm16 (ENTER/RET imm).
    I16,
    /// imm32.
    I32,
    /// Implicit: rAX, rDX pair.
    ZoAxDx,
    /// Far address.
    FarPtr,
    /// Memory-only (LEA style).
    MemDirect,
}

impl InstrFormat {
    /// `true` if the format involves a `ModRM` byte.
    #[must_use]
    pub const fn has_modrm(self) -> bool {
        matches!(
            self,
            Self::MR
                | Self::RM
                | Self::RMI8
                | Self::RMI16
                | Self::RMI32
                | Self::MI8
                | Self::MI16
                | Self::MI32
                | Self::M
                | Self::MC
                | Self::M1S
                | Self::RVM
                | Self::RVMR
                | Self::MemDirect
                | Self::M1
        )
    }

    /// Minimum additional bytes after opcode (excluding ModRM/SIB/disp).
    #[must_use]
    pub const fn min_imm_bytes(self) -> usize {
        match self {
            Self::MI8 | Self::RMI8 | Self::I8 | Self::D8 | Self::M1S => 1,
            Self::MI16 | Self::RMI16 | Self::I16 => 2,
            Self::MI32 | Self::RMI32 | Self::I32 | Self::D32 => 4,
            _ => 0,
        }
    }
}

// ---------------------------------------------------------------------------
// PrefixHandler
// ---------------------------------------------------------------------------

/// Kind of prefix associated with an opcode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PrefixHandler {
    /// No mandatory prefix.
    None,
    /// Mandatory 0x66 prefix (operand-size).
    P66,
    /// Mandatory 0xF2 prefix (REPNZ / scalar double).
    PF2,
    /// Mandatory 0xF3 prefix (REP / scalar single).
    PF3,
    /// REX.W required for 64-bit form.
    RexW,
    // Note: dedicated `Vex128`/`Vex256`/`Evex` variants were removed as dead
    // scaffolding — nothing in this table ever constructed them; VEX/EVEX
    // decoding is instead handled by `iced_x86::Decoder` upstream, and
    // AVX/AVX2 lifting lives in `lift.rs`'s dispatch table.
}

impl std::fmt::Display for PrefixHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::None => "",
            Self::P66 => "66 ",
            Self::PF2 => "F2 ",
            Self::PF3 => "F3 ",
            Self::RexW => "REX.W ",
        };
        write!(f, "{s}")
    }
}

// ---------------------------------------------------------------------------
// OpcodeGroup — /digit extension
// ---------------------------------------------------------------------------

/// Extension via the `/digit` (reg field of `ModRM` byte).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OpcodeGroup {
    /// No group extension; the opcode is fully determined.
    None,
    /// Group 1 (0x80–0x83): ADD/OR/ADC/SBB/AND/SUB/XOR/CMP.
    Group1,
    /// Group 1a (0x8F): POP.
    Group1A,
    /// Group 2 (0xC0/0xC1/0xD0–0xD3): ROL/ROR/RCL/RCR/SHL/SHR/SAR.
    Group2,
    /// Group 3 (0xF6/0xF7): TEST/NOT/NEG/MUL/IMUL/DIV/IDIV.
    Group3,
    /// Group 4 (0xFE): INC/DEC (r/m8).
    Group4,
    /// Group 5 (0xFF): INC/DEC/CALL/CALLF/JMP/JMPF/PUSH.
    Group5,
    /// Group 6 (0F 00): SLDT/STR/LLDT/LTR/VERR/VERW.
    Group6,
    /// Group 7 (0F 01): SGDT/SIDT/LGDT/LIDT/SMSW/LMSW/INVLPG.
    Group7,
    /// Group 8 (0F BA): BT/BTS/BTR/BTC.
    Group8,
    /// Group 9 (0F C7): CMPXCHG8B/VMPTRLD/VMCLEAR/VMXON/RDRAND/RDSEED.
    Group9,
    /// Group 11 (0xC6/0xC7): MOV imm.
    Group11,
    /// Group 12 (0F 71): PSRLW/PSRAW/PSLLW by imm8.
    Group12,
    /// Group 13 (0F 72): PSRLD/PSRAD/PSLLD by imm8.
    Group13,
    /// Group 14 (0F 73): PSRLQ/PSRLDQ/PSLLQ/PSLLDQ by imm8.
    Group14,
    /// Group 15 (0F AE): FXSAVE/FXRSTOR/LDMXCSR/STMXCSR/XSAVE/XRSTOR/CLFLUSH/SFENCE/LFENCE/MFENCE.
    Group15,
    /// Group 16 (0F 18): PREFETCH.
    Group16,
    /// Group 17 (VEX+0F AE): VLDMXCSR/VSTMXCSR.
    Group17,
}

// ---------------------------------------------------------------------------
// OpcodeEntry
// ---------------------------------------------------------------------------

/// A single decoded opcode table entry.
#[derive(Debug, Clone)]
pub struct OpcodeEntry {
    /// Primary opcode byte (or extended byte).
    pub opcode: u8,
    /// Second byte for 0F xx / 0F 38 xx / 0F 3A xx escapes.
    pub opcode2: Option<u8>,
    /// Third byte for 0F 38/3A escapes.
    pub opcode3: Option<u8>,
    /// Canonical mnemonic.
    pub mnemonic: &'static str,
    /// Operand encoding format.
    pub format: InstrFormat,
    /// Mandatory prefix (or None).
    pub prefix: PrefixHandler,
    /// Group extension (/digit), or None.
    pub group: OpcodeGroup,
    /// Brief description.
    pub desc: &'static str,
    /// `true` if this is a privileged instruction.
    pub privileged: bool,
    /// `true` if this instruction may raise an exception (#UD, #GP, etc.).
    pub may_fault: bool,
}

impl OpcodeEntry {
    const fn new(
        opcode: u8,
        mnemonic: &'static str,
        format: InstrFormat,
        prefix: PrefixHandler,
        desc: &'static str,
    ) -> Self {
        Self {
            opcode,
            opcode2: None,
            opcode3: None,
            mnemonic,
            format,
            prefix,
            group: OpcodeGroup::None,
            desc,
            privileged: false,
            may_fault: false,
        }
    }

    const fn with_group(mut self, g: OpcodeGroup) -> Self {
        self.group = g;
        self
    }

    const fn privileged(mut self) -> Self {
        self.privileged = true;
        self
    }

    const fn faults(mut self) -> Self {
        self.may_fault = true;
        self
    }

    /// `true` if this opcode is a near branch.
    #[must_use]
    pub fn is_branch(&self) -> bool {
        matches!(
            self.mnemonic,
            "jmp"
                | "call"
                | "ret"
                | "retf"
                | "jcc"
                | "jo"
                | "jno"
                | "jb"
                | "jae"
                | "je"
                | "jne"
                | "jbe"
                | "ja"
                | "js"
                | "jns"
                | "jp"
                | "jnp"
                | "jl"
                | "jge"
                | "jle"
                | "jg"
                | "loop"
                | "loopz"
                | "loopnz"
                | "jcxz"
                | "jecxz"
                | "jrcxz"
        )
    }

    /// `true` if this opcode accesses memory.
    #[must_use]
    pub fn accesses_memory(&self) -> bool {
        self.format.has_modrm()
    }
}

// ---------------------------------------------------------------------------
// Escape0F, Escape0F38, Escape0F3A  — two/three-byte escape tables
// ---------------------------------------------------------------------------

/// Two-byte opcode 0F xx space.
#[derive(Debug, Clone)]
pub struct Escape0F(pub Vec<OpcodeEntry>);

/// Three-byte 0F 38 xx space.
#[derive(Debug, Clone)]
pub struct Escape0F38(pub Vec<OpcodeEntry>);

/// Three-byte 0F 3A xx space.
#[derive(Debug, Clone)]
pub struct Escape0F3A(pub Vec<OpcodeEntry>);

impl Escape0F {
    /// Build the standard 0F xx table.
    #[must_use]
    pub fn build() -> Self {
        let mut entries = Vec::with_capacity(256);
        // --- 0F 00 – 0F 0F ---
        entries.push(
            OpcodeEntry::new(
                0x00,
                "lldt/sldt",
                InstrFormat::M,
                PrefixHandler::None,
                "Group 6",
            )
            .with_group(OpcodeGroup::Group6),
        );
        entries.push(
            OpcodeEntry::new(
                0x01,
                "lgdt/sgdt",
                InstrFormat::M,
                PrefixHandler::None,
                "Group 7",
            )
            .with_group(OpcodeGroup::Group7),
        );
        entries.push(OpcodeEntry::new(
            0x05,
            "syscall",
            InstrFormat::ZO,
            PrefixHandler::None,
            "Fast system call",
        ));
        entries.push(
            OpcodeEntry::new(
                0x06,
                "clts",
                InstrFormat::ZO,
                PrefixHandler::None,
                "Clear task-switched flag",
            )
            .privileged(),
        );
        entries.push(
            OpcodeEntry::new(
                0x07,
                "sysret",
                InstrFormat::ZO,
                PrefixHandler::None,
                "Return from fast system call",
            )
            .privileged(),
        );
        entries.push(
            OpcodeEntry::new(
                0x08,
                "invd",
                InstrFormat::ZO,
                PrefixHandler::None,
                "Invalidate cache",
            )
            .privileged(),
        );
        entries.push(
            OpcodeEntry::new(
                0x09,
                "wbinvd",
                InstrFormat::ZO,
                PrefixHandler::None,
                "Write-back and invalidate cache",
            )
            .privileged(),
        );
        entries.push(
            OpcodeEntry::new(
                0x0B,
                "ud2",
                InstrFormat::ZO,
                PrefixHandler::None,
                "Undefined instruction",
            )
            .faults(),
        );
        entries.push(
            OpcodeEntry::new(
                0x0D,
                "prefetch",
                InstrFormat::M,
                PrefixHandler::None,
                "AMD Prefetch",
            )
            .with_group(OpcodeGroup::Group16),
        );
        entries.push(OpcodeEntry::new(
            0x0F,
            "3dnow",
            InstrFormat::MR,
            PrefixHandler::None,
            "3DNow! prefix",
        ));
        // --- 0F 10 – 0F 17 ---
        entries.push(OpcodeEntry::new(
            0x10,
            "movups",
            InstrFormat::RM,
            PrefixHandler::None,
            "Move unaligned packed single",
        ));
        entries.push(OpcodeEntry::new(
            0x10,
            "movupd",
            InstrFormat::RM,
            PrefixHandler::P66,
            "Move unaligned packed double",
        ));
        entries.push(OpcodeEntry::new(
            0x10,
            "movss",
            InstrFormat::RM,
            PrefixHandler::PF3,
            "Move scalar single",
        ));
        entries.push(OpcodeEntry::new(
            0x10,
            "movsd",
            InstrFormat::RM,
            PrefixHandler::PF2,
            "Move scalar double",
        ));
        entries.push(OpcodeEntry::new(
            0x11,
            "movups",
            InstrFormat::MR,
            PrefixHandler::None,
            "Move unaligned packed single (store)",
        ));
        entries.push(OpcodeEntry::new(
            0x11,
            "movupd",
            InstrFormat::MR,
            PrefixHandler::P66,
            "Move unaligned packed double (store)",
        ));
        entries.push(OpcodeEntry::new(
            0x11,
            "movss",
            InstrFormat::MR,
            PrefixHandler::PF3,
            "Move scalar single (store)",
        ));
        entries.push(OpcodeEntry::new(
            0x11,
            "movsd",
            InstrFormat::MR,
            PrefixHandler::PF2,
            "Move scalar double (store)",
        ));
        entries.push(OpcodeEntry::new(
            0x14,
            "unpcklps",
            InstrFormat::RM,
            PrefixHandler::None,
            "Unpack low packed single",
        ));
        entries.push(OpcodeEntry::new(
            0x15,
            "unpckhps",
            InstrFormat::RM,
            PrefixHandler::None,
            "Unpack high packed single",
        ));
        entries.push(OpcodeEntry::new(
            0x16,
            "movhps",
            InstrFormat::RM,
            PrefixHandler::None,
            "Move high packed single",
        ));
        entries.push(OpcodeEntry::new(
            0x17,
            "movhps",
            InstrFormat::MR,
            PrefixHandler::None,
            "Move high packed single (store)",
        ));
        // --- 0F 18 ---
        entries.push(
            OpcodeEntry::new(
                0x18,
                "prefetch",
                InstrFormat::M,
                PrefixHandler::None,
                "Prefetch",
            )
            .with_group(OpcodeGroup::Group16),
        );
        // --- 0F 1F ---
        entries.push(OpcodeEntry::new(
            0x1F,
            "nop",
            InstrFormat::M,
            PrefixHandler::None,
            "Multi-byte NOP",
        ));
        // --- 0F 20–0F 23 ---
        entries.push(
            OpcodeEntry::new(
                0x20,
                "mov",
                InstrFormat::MR,
                PrefixHandler::None,
                "Move from CR",
            )
            .privileged(),
        );
        entries.push(
            OpcodeEntry::new(
                0x21,
                "mov",
                InstrFormat::MR,
                PrefixHandler::None,
                "Move from DR",
            )
            .privileged(),
        );
        entries.push(
            OpcodeEntry::new(
                0x22,
                "mov",
                InstrFormat::RM,
                PrefixHandler::None,
                "Move to CR",
            )
            .privileged(),
        );
        entries.push(
            OpcodeEntry::new(
                0x23,
                "mov",
                InstrFormat::RM,
                PrefixHandler::None,
                "Move to DR",
            )
            .privileged(),
        );
        // --- 0F 28–0F 2F ---
        entries.push(OpcodeEntry::new(
            0x28,
            "movaps",
            InstrFormat::RM,
            PrefixHandler::None,
            "Move aligned packed single",
        ));
        entries.push(OpcodeEntry::new(
            0x28,
            "movapd",
            InstrFormat::RM,
            PrefixHandler::P66,
            "Move aligned packed double",
        ));
        entries.push(OpcodeEntry::new(
            0x29,
            "movaps",
            InstrFormat::MR,
            PrefixHandler::None,
            "Move aligned packed single (store)",
        ));
        entries.push(OpcodeEntry::new(
            0x29,
            "movapd",
            InstrFormat::MR,
            PrefixHandler::P66,
            "Move aligned packed double (store)",
        ));
        entries.push(OpcodeEntry::new(
            0x2A,
            "cvtpi2ps",
            InstrFormat::RM,
            PrefixHandler::None,
            "Convert packed int32 to packed single",
        ));
        entries.push(OpcodeEntry::new(
            0x2A,
            "cvtsi2ss",
            InstrFormat::RM,
            PrefixHandler::PF3,
            "Convert int32/64 to scalar single",
        ));
        entries.push(OpcodeEntry::new(
            0x2A,
            "cvtsi2sd",
            InstrFormat::RM,
            PrefixHandler::PF2,
            "Convert int32/64 to scalar double",
        ));
        entries.push(OpcodeEntry::new(
            0x2C,
            "cvttps2pi",
            InstrFormat::RM,
            PrefixHandler::None,
            "Convert with truncation packed single to packed int32",
        ));
        entries.push(OpcodeEntry::new(
            0x2C,
            "cvttss2si",
            InstrFormat::RM,
            PrefixHandler::PF3,
            "Convert with truncation scalar single to int32/64",
        ));
        entries.push(OpcodeEntry::new(
            0x2C,
            "cvttsd2si",
            InstrFormat::RM,
            PrefixHandler::PF2,
            "Convert with truncation scalar double to int32/64",
        ));
        entries.push(OpcodeEntry::new(
            0x2E,
            "ucomiss",
            InstrFormat::RM,
            PrefixHandler::None,
            "Unordered compare scalar single",
        ));
        entries.push(OpcodeEntry::new(
            0x2E,
            "ucomisd",
            InstrFormat::RM,
            PrefixHandler::P66,
            "Unordered compare scalar double",
        ));
        entries.push(OpcodeEntry::new(
            0x2F,
            "comiss",
            InstrFormat::RM,
            PrefixHandler::None,
            "Compare scalar single",
        ));
        entries.push(OpcodeEntry::new(
            0x2F,
            "comisd",
            InstrFormat::RM,
            PrefixHandler::P66,
            "Compare scalar double",
        ));
        // --- 0F 30–0F 3F System ---
        entries.push(
            OpcodeEntry::new(
                0x30,
                "wrmsr",
                InstrFormat::ZO,
                PrefixHandler::None,
                "Write MSR",
            )
            .privileged(),
        );
        entries.push(OpcodeEntry::new(
            0x31,
            "rdtsc",
            InstrFormat::ZO,
            PrefixHandler::None,
            "Read time-stamp counter",
        ));
        entries.push(
            OpcodeEntry::new(
                0x32,
                "rdmsr",
                InstrFormat::ZO,
                PrefixHandler::None,
                "Read MSR",
            )
            .privileged(),
        );
        entries.push(OpcodeEntry::new(
            0x33,
            "rdpmc",
            InstrFormat::ZO,
            PrefixHandler::None,
            "Read performance monitoring counter",
        ));
        entries.push(OpcodeEntry::new(
            0x34,
            "sysenter",
            InstrFormat::ZO,
            PrefixHandler::None,
            "Fast system call (SYSENTER)",
        ));
        entries.push(
            OpcodeEntry::new(
                0x35,
                "sysexit",
                InstrFormat::ZO,
                PrefixHandler::None,
                "Fast system call return (SYSEXIT)",
            )
            .privileged(),
        );
        entries.push(OpcodeEntry::new(
            0x37,
            "getsec",
            InstrFormat::ZO,
            PrefixHandler::None,
            "GETSEC SMX",
        ));
        // --- Conditional moves 0F 40–0F 4F ---
        for (i, mn) in [
            "cmovo", "cmovno", "cmovb", "cmovae", "cmove", "cmovne", "cmovbe", "cmova", "cmovs",
            "cmovns", "cmovp", "cmovnp", "cmovl", "cmovge", "cmovle", "cmovg",
        ]
        .iter()
        .enumerate()
        {
            entries.push(OpcodeEntry::new(
                0x40 + i as u8,
                mn,
                InstrFormat::RM,
                PrefixHandler::None,
                "Conditional move",
            ));
        }
        // --- 0F 50–0F 5F SSE arithmetic ---
        let sse_arith: &[(&str, &str)] = &[
            ("movmskps", "Move mask packed single"),
            ("sqrtps", "Sqrt packed single"),
            ("rsqrtps", "Reciprocal sqrt"),
            ("rcpps", "Reciprocal"),
            ("andps", "Bitwise AND packed single"),
            ("andnps", "Bitwise ANDN"),
            ("orps", "Bitwise OR packed single"),
            ("xorps", "Bitwise XOR"),
            ("addps", "Add packed single"),
            ("mulps", "Multiply packed single"),
            ("cvtps2pd", "Convert packed single to double"),
            ("cvtdq2ps", "Convert dword to packed single"),
            ("subps", "Sub packed single"),
            ("minps", "Min packed single"),
            ("divps", "Div packed single"),
            ("maxps", "Max packed single"),
        ];
        for (i, (mn, desc)) in sse_arith.iter().enumerate() {
            entries.push(OpcodeEntry::new(
                0x50 + i as u8,
                mn,
                InstrFormat::RM,
                PrefixHandler::None,
                desc,
            ));
        }
        // --- 0F 60–0F 6F MMX/SSE ---
        entries.push(OpcodeEntry::new(
            0x6E,
            "movd/movq",
            InstrFormat::RM,
            PrefixHandler::P66,
            "Move doubleword/quadword",
        ));
        entries.push(OpcodeEntry::new(
            0x6F,
            "movdqa",
            InstrFormat::RM,
            PrefixHandler::P66,
            "Move aligned double quadword",
        ));
        entries.push(OpcodeEntry::new(
            0x6F,
            "movdqu",
            InstrFormat::RM,
            PrefixHandler::PF3,
            "Move unaligned double quadword",
        ));
        // --- Jcc long 0F 80–0F 8F ---
        let jcc: &[(&str, &str)] = &[
            ("jo", "Jump if overflow"),
            ("jno", "Jump if not overflow"),
            ("jb", "Jump if below"),
            ("jae", "Jump if above/equal"),
            ("je", "Jump if equal"),
            ("jne", "Jump if not equal"),
            ("jbe", "Jump if below/equal"),
            ("ja", "Jump if above"),
            ("js", "Jump if sign"),
            ("jns", "Jump if not sign"),
            ("jp", "Jump if parity"),
            ("jnp", "Jump if not parity"),
            ("jl", "Jump if less"),
            ("jge", "Jump if greater/equal"),
            ("jle", "Jump if less/equal"),
            ("jg", "Jump if greater"),
        ];
        for (i, (mn, desc)) in jcc.iter().enumerate() {
            entries.push(OpcodeEntry::new(
                0x80 + i as u8,
                mn,
                InstrFormat::D32,
                PrefixHandler::None,
                desc,
            ));
        }
        // --- SETcc 0F 90–0F 9F ---
        let setcc = [
            "seto", "setno", "setb", "setae", "sete", "setne", "setbe", "seta", "sets", "setns",
            "setp", "setnp", "setl", "setge", "setle", "setg",
        ];
        for (i, mn) in setcc.iter().enumerate() {
            entries.push(OpcodeEntry::new(
                0x90 + i as u8,
                mn,
                InstrFormat::M,
                PrefixHandler::None,
                "Set byte on condition",
            ));
        }
        // --- 0F A0–0F AF ---
        entries.push(OpcodeEntry::new(
            0xA0,
            "push fs",
            InstrFormat::ZO,
            PrefixHandler::None,
            "Push FS",
        ));
        entries.push(OpcodeEntry::new(
            0xA1,
            "pop fs",
            InstrFormat::ZO,
            PrefixHandler::None,
            "Pop FS",
        ));
        entries.push(OpcodeEntry::new(
            0xA2,
            "cpuid",
            InstrFormat::ZO,
            PrefixHandler::None,
            "CPU identification",
        ));
        entries.push(OpcodeEntry::new(
            0xA3,
            "bt",
            InstrFormat::MR,
            PrefixHandler::None,
            "Bit test",
        ));
        entries.push(OpcodeEntry::new(
            0xA4,
            "shld",
            InstrFormat::MRI8,
            PrefixHandler::None,
            "Double-precision shift left by imm8",
        ));
        entries.push(OpcodeEntry::new(
            0xA5,
            "shld",
            InstrFormat::MC,
            PrefixHandler::None,
            "Double-precision shift left by CL",
        ));
        entries.push(OpcodeEntry::new(
            0xA8,
            "push gs",
            InstrFormat::ZO,
            PrefixHandler::None,
            "Push GS",
        ));
        entries.push(OpcodeEntry::new(
            0xA9,
            "pop gs",
            InstrFormat::ZO,
            PrefixHandler::None,
            "Pop GS",
        ));
        entries.push(OpcodeEntry::new(
            0xAB,
            "bts",
            InstrFormat::MR,
            PrefixHandler::None,
            "Bit test and set",
        ));
        entries.push(OpcodeEntry::new(
            0xAC,
            "shrd",
            InstrFormat::MRI8,
            PrefixHandler::None,
            "Double-precision shift right by imm8",
        ));
        entries.push(OpcodeEntry::new(
            0xAD,
            "shrd",
            InstrFormat::MC,
            PrefixHandler::None,
            "Double-precision shift right by CL",
        ));
        entries.push(
            OpcodeEntry::new(
                0xAE,
                "group15",
                InstrFormat::M,
                PrefixHandler::None,
                "Group 15",
            )
            .with_group(OpcodeGroup::Group15),
        );
        entries.push(OpcodeEntry::new(
            0xAF,
            "imul",
            InstrFormat::RM,
            PrefixHandler::None,
            "Signed multiply",
        ));
        // --- 0F B0–0F BF ---
        entries.push(OpcodeEntry::new(
            0xB0,
            "cmpxchg",
            InstrFormat::MR,
            PrefixHandler::None,
            "Compare and exchange (byte)",
        ));
        entries.push(OpcodeEntry::new(
            0xB1,
            "cmpxchg",
            InstrFormat::MR,
            PrefixHandler::None,
            "Compare and exchange",
        ));
        entries.push(OpcodeEntry::new(
            0xB3,
            "btr",
            InstrFormat::MR,
            PrefixHandler::None,
            "Bit test and reset",
        ));
        entries.push(OpcodeEntry::new(
            0xB6,
            "movzx",
            InstrFormat::RM,
            PrefixHandler::None,
            "Move with zero-extend (byte)",
        ));
        entries.push(OpcodeEntry::new(
            0xB7,
            "movzx",
            InstrFormat::RM,
            PrefixHandler::None,
            "Move with zero-extend (word)",
        ));
        entries.push(
            OpcodeEntry::new(
                0xBA,
                "group8",
                InstrFormat::MI8,
                PrefixHandler::None,
                "Group 8 bit ops",
            )
            .with_group(OpcodeGroup::Group8),
        );
        entries.push(OpcodeEntry::new(
            0xBB,
            "btc",
            InstrFormat::MR,
            PrefixHandler::None,
            "Bit test and complement",
        ));
        entries.push(OpcodeEntry::new(
            0xBC,
            "bsf",
            InstrFormat::RM,
            PrefixHandler::None,
            "Bit scan forward",
        ));
        entries.push(OpcodeEntry::new(
            0xBD,
            "bsr",
            InstrFormat::RM,
            PrefixHandler::None,
            "Bit scan reverse",
        ));
        entries.push(OpcodeEntry::new(
            0xBE,
            "movsx",
            InstrFormat::RM,
            PrefixHandler::None,
            "Move with sign-extend (byte)",
        ));
        entries.push(OpcodeEntry::new(
            0xBF,
            "movsx",
            InstrFormat::RM,
            PrefixHandler::None,
            "Move with sign-extend (word)",
        ));
        // --- 0F C0–0F CF ---
        entries.push(OpcodeEntry::new(
            0xC0,
            "xadd",
            InstrFormat::MR,
            PrefixHandler::None,
            "Exchange and add (byte)",
        ));
        entries.push(OpcodeEntry::new(
            0xC1,
            "xadd",
            InstrFormat::MR,
            PrefixHandler::None,
            "Exchange and add",
        ));
        entries.push(OpcodeEntry::new(
            0xC2,
            "cmpps",
            InstrFormat::RVMR,
            PrefixHandler::None,
            "Compare packed single",
        ));
        entries.push(OpcodeEntry::new(
            0xC3,
            "movnti",
            InstrFormat::MR,
            PrefixHandler::None,
            "Store doubleword using non-temporal hint",
        ));
        entries.push(OpcodeEntry::new(
            0xC4,
            "pinsrw",
            InstrFormat::RMI8,
            PrefixHandler::P66,
            "Insert word",
        ));
        entries.push(OpcodeEntry::new(
            0xC5,
            "pextrw",
            InstrFormat::RMI8,
            PrefixHandler::P66,
            "Extract word",
        ));
        entries.push(OpcodeEntry::new(
            0xC6,
            "shufps",
            InstrFormat::RMI8,
            PrefixHandler::None,
            "Shuffle packed single",
        ));
        entries.push(
            OpcodeEntry::new(
                0xC7,
                "group9",
                InstrFormat::M,
                PrefixHandler::None,
                "Group 9",
            )
            .with_group(OpcodeGroup::Group9),
        );
        // BSWAP 0F C8–0F CF
        for i in 0u8..8 {
            entries.push(OpcodeEntry::new(
                0xC8 + i,
                "bswap",
                InstrFormat::O,
                PrefixHandler::None,
                "Byte swap",
            ));
        }
        // --- 0F D0–0F FF SSE2 arithmetic ---
        entries.push(OpcodeEntry::new(
            0xD0,
            "addsubps",
            InstrFormat::RM,
            PrefixHandler::PF2,
            "Add/sub packed single",
        ));
        entries.push(OpcodeEntry::new(
            0xD1,
            "psrlw",
            InstrFormat::RM,
            PrefixHandler::P66,
            "Shift packed words right logical",
        ));
        entries.push(OpcodeEntry::new(
            0xD5,
            "pmullw",
            InstrFormat::RM,
            PrefixHandler::P66,
            "Multiply packed signed word integers low",
        ));
        entries.push(OpcodeEntry::new(
            0xD8,
            "psubusb",
            InstrFormat::RM,
            PrefixHandler::P66,
            "Subtract packed unsigned byte integers with unsigned saturation",
        ));
        entries.push(OpcodeEntry::new(
            0xE8,
            "psubsb",
            InstrFormat::RM,
            PrefixHandler::P66,
            "Subtract packed signed byte integers with signed saturation",
        ));
        entries.push(OpcodeEntry::new(
            0xEF,
            "pxor",
            InstrFormat::RM,
            PrefixHandler::P66,
            "Logical exclusive OR",
        ));
        entries.push(OpcodeEntry::new(
            0xF0,
            "lddqu",
            InstrFormat::RM,
            PrefixHandler::PF2,
            "Load unaligned integer 128 bits",
        ));
        entries.push(OpcodeEntry::new(
            0xFC,
            "paddb",
            InstrFormat::RM,
            PrefixHandler::P66,
            "Add packed byte integers",
        ));
        entries.push(OpcodeEntry::new(
            0xFD,
            "paddw",
            InstrFormat::RM,
            PrefixHandler::P66,
            "Add packed word integers",
        ));
        entries.push(OpcodeEntry::new(
            0xFE,
            "paddd",
            InstrFormat::RM,
            PrefixHandler::P66,
            "Add packed doubleword integers",
        ));
        Self(entries)
    }

    /// Look up an entry by opcode byte and optional mandatory prefix.
    #[must_use]
    pub fn lookup(&self, opcode: u8, prefix: PrefixHandler) -> Option<&OpcodeEntry> {
        self.0
            .iter()
            .find(|e| e.opcode == opcode && e.prefix == prefix)
            .or_else(|| {
                self.0
                    .iter()
                    .find(|e| e.opcode == opcode && e.prefix == PrefixHandler::None)
            })
    }
}

impl Escape0F38 {
    /// Build the 0F 38 xx table (SSE4.1/4.2, AESNI, SHA, etc.).
    #[must_use]
    pub fn build() -> Self {
        let mut entries = Vec::with_capacity(64);
        // PSHUFB
        entries.push(OpcodeEntry::new(
            0x00,
            "pshufb",
            InstrFormat::RM,
            PrefixHandler::P66,
            "Shuffle packed bytes",
        ));
        // PHADDW / PHADD PHADDD / PHSUBW / etc.
        for (b, mn) in [
            (0x01_u8, "phaddw"),
            (0x02, "phaddd"),
            (0x03, "phaddsw"),
            (0x04, "pmaddubsw"),
            (0x05, "phsubw"),
            (0x06, "phsubd"),
            (0x07, "phsubsw"),
            (0x08, "psignb"),
            (0x09, "psignw"),
            (0x0A, "psignd"),
            (0x0B, "pmulhrsw"),
        ] {
            entries.push(OpcodeEntry::new(
                b,
                mn,
                InstrFormat::RM,
                PrefixHandler::P66,
                mn,
            ));
        }
        // SSE4.1
        for (b, mn) in [
            (0x20_u8, "pmovsxbw"),
            (0x21, "pmovsxbd"),
            (0x22, "pmovsxbq"),
            (0x23, "pmovsxwd"),
            (0x24, "pmovsxwq"),
            (0x25, "pmovsxdq"),
            (0x28, "pmuldq"),
            (0x29, "pcmpeqq"),
            (0x2A, "movntdqa"),
            (0x2B, "packusdw"),
            (0x30, "pmovzxbw"),
            (0x31, "pmovzxbd"),
            (0x32, "pmovzxbq"),
            (0x33, "pmovzxwd"),
            (0x34, "pmovzxwq"),
            (0x35, "pmovzxdq"),
            (0x37, "pcmpgtq"),
            (0x38, "pminsb"),
            (0x39, "pminsd"),
            (0x3A, "pminuw"),
            (0x3B, "pminud"),
            (0x3C, "pmaxsb"),
            (0x3D, "pmaxsd"),
            (0x3E, "pmaxuw"),
            (0x3F, "pmaxud"),
            (0x40, "pmulld"),
            (0x41, "phminposuw"),
        ] {
            entries.push(OpcodeEntry::new(
                b,
                mn,
                InstrFormat::RM,
                PrefixHandler::P66,
                mn,
            ));
        }
        // AES-NI
        for (b, mn) in [
            (0xDB_u8, "aesimc"),
            (0xDC, "aesenc"),
            (0xDD, "aesenclast"),
            (0xDE, "aesdec"),
            (0xDF, "aesdeclast"),
        ] {
            entries.push(OpcodeEntry::new(
                b,
                mn,
                InstrFormat::RM,
                PrefixHandler::P66,
                mn,
            ));
        }
        // SHA
        for (b, mn) in [
            (0xC8_u8, "sha1nexte"),
            (0xC9, "sha1msg1"),
            (0xCA, "sha1msg2"),
            (0xCB, "sha256rnds2"),
            (0xCC, "sha256msg1"),
            (0xCD, "sha256msg2"),
        ] {
            entries.push(OpcodeEntry::new(
                b,
                mn,
                InstrFormat::RM,
                PrefixHandler::None,
                mn,
            ));
        }
        // CRC32 (F2 prefix)
        entries.push(OpcodeEntry::new(
            0xF0,
            "crc32",
            InstrFormat::RM,
            PrefixHandler::PF2,
            "CRC32 byte",
        ));
        entries.push(OpcodeEntry::new(
            0xF1,
            "crc32",
            InstrFormat::RM,
            PrefixHandler::PF2,
            "CRC32 word/dword/qword",
        ));
        Self(entries)
    }

    #[must_use]
    pub fn lookup(&self, opcode: u8, prefix: PrefixHandler) -> Option<&OpcodeEntry> {
        self.0
            .iter()
            .find(|e| e.opcode == opcode && e.prefix == prefix)
            .or_else(|| self.0.iter().find(|e| e.opcode == opcode))
    }
}

impl Escape0F3A {
    /// Build the 0F 3A xx table (PCLMUL, insertps, roundss/sd, etc.).
    #[must_use]
    pub fn build() -> Self {
        let mut entries = Vec::with_capacity(32);
        entries.push(OpcodeEntry::new(
            0x08,
            "roundps",
            InstrFormat::RMI8,
            PrefixHandler::P66,
            "Round packed single",
        ));
        entries.push(OpcodeEntry::new(
            0x09,
            "roundpd",
            InstrFormat::RMI8,
            PrefixHandler::P66,
            "Round packed double",
        ));
        entries.push(OpcodeEntry::new(
            0x0A,
            "roundss",
            InstrFormat::RMI8,
            PrefixHandler::P66,
            "Round scalar single",
        ));
        entries.push(OpcodeEntry::new(
            0x0B,
            "roundsd",
            InstrFormat::RMI8,
            PrefixHandler::P66,
            "Round scalar double",
        ));
        entries.push(OpcodeEntry::new(
            0x0C,
            "blendps",
            InstrFormat::RMI8,
            PrefixHandler::P66,
            "Blend packed single",
        ));
        entries.push(OpcodeEntry::new(
            0x0D,
            "blendpd",
            InstrFormat::RMI8,
            PrefixHandler::P66,
            "Blend packed double",
        ));
        entries.push(OpcodeEntry::new(
            0x0E,
            "pblendw",
            InstrFormat::RMI8,
            PrefixHandler::P66,
            "Blend packed words",
        ));
        entries.push(OpcodeEntry::new(
            0x0F,
            "palignr",
            InstrFormat::RMI8,
            PrefixHandler::P66,
            "Packed align right",
        ));
        entries.push(OpcodeEntry::new(
            0x14,
            "pextrb",
            InstrFormat::MRI8,
            PrefixHandler::P66,
            "Extract byte",
        ));
        entries.push(OpcodeEntry::new(
            0x15,
            "pextrw",
            InstrFormat::MRI8,
            PrefixHandler::P66,
            "Extract word",
        ));
        entries.push(OpcodeEntry::new(
            0x16,
            "pextrd",
            InstrFormat::MRI8,
            PrefixHandler::P66,
            "Extract dword",
        ));
        entries.push(OpcodeEntry::new(
            0x17,
            "extractps",
            InstrFormat::MRI8,
            PrefixHandler::P66,
            "Extract packed single",
        ));
        entries.push(OpcodeEntry::new(
            0x20,
            "pinsrb",
            InstrFormat::RMI8,
            PrefixHandler::P66,
            "Insert byte",
        ));
        entries.push(OpcodeEntry::new(
            0x21,
            "insertps",
            InstrFormat::RMI8,
            PrefixHandler::P66,
            "Insert packed single",
        ));
        entries.push(OpcodeEntry::new(
            0x22,
            "pinsrd",
            InstrFormat::RMI8,
            PrefixHandler::P66,
            "Insert dword",
        ));
        entries.push(OpcodeEntry::new(
            0x40,
            "dpps",
            InstrFormat::RMI8,
            PrefixHandler::P66,
            "Dot product packed single",
        ));
        entries.push(OpcodeEntry::new(
            0x41,
            "dppd",
            InstrFormat::RMI8,
            PrefixHandler::P66,
            "Dot product packed double",
        ));
        entries.push(OpcodeEntry::new(
            0x42,
            "mpsadbw",
            InstrFormat::RMI8,
            PrefixHandler::P66,
            "Multi-precision sum of absolute diffs of bytes",
        ));
        entries.push(OpcodeEntry::new(
            0x44,
            "pclmulqdq",
            InstrFormat::RMI8,
            PrefixHandler::P66,
            "Carry-less multiplication quadword",
        ));
        entries.push(OpcodeEntry::new(
            0x60,
            "pcmpestrm",
            InstrFormat::RMI8,
            PrefixHandler::P66,
            "Packed compare explicit length strings, return mask",
        ));
        entries.push(OpcodeEntry::new(
            0x61,
            "pcmpestri",
            InstrFormat::RMI8,
            PrefixHandler::P66,
            "Packed compare explicit length strings, return index",
        ));
        entries.push(OpcodeEntry::new(
            0x62,
            "pcmpistrm",
            InstrFormat::RMI8,
            PrefixHandler::P66,
            "Packed compare implicit length strings, return mask",
        ));
        entries.push(OpcodeEntry::new(
            0x63,
            "pcmpistri",
            InstrFormat::RMI8,
            PrefixHandler::P66,
            "Packed compare implicit length strings, return index",
        ));
        entries.push(OpcodeEntry::new(
            0xCC,
            "sha1rnds4",
            InstrFormat::RMI8,
            PrefixHandler::None,
            "SHA1 round",
        ));
        entries.push(OpcodeEntry::new(
            0xDF,
            "aeskeygenassist",
            InstrFormat::RMI8,
            PrefixHandler::P66,
            "AES key generation assist",
        ));
        Self(entries)
    }

    #[must_use]
    pub fn lookup(&self, opcode: u8, prefix: PrefixHandler) -> Option<&OpcodeEntry> {
        self.0
            .iter()
            .find(|e| e.opcode == opcode && e.prefix == prefix)
            .or_else(|| self.0.iter().find(|e| e.opcode == opcode))
    }
}

// ---------------------------------------------------------------------------
// X86DecodeTable — the main table
// ---------------------------------------------------------------------------

/// Primary one-byte opcode decode table plus escape sub-tables.
pub struct X86DecodeTable {
    /// One-byte primary opcode entries (multiple entries per opcode possible).
    pub primary: Vec<OpcodeEntry>,
    /// 0F xx two-byte escape table.
    pub escape_0f: Escape0F,
    /// 0F 38 xx three-byte escape table.
    pub escape_0f38: Escape0F38,
    /// 0F 3A xx three-byte escape table.
    pub escape_0f3a: Escape0F3A,
}

impl X86DecodeTable {
    /// Build the full x86-64 decode table.
    #[must_use]
    pub fn build() -> Self {
        let primary = Self::build_primary();
        Self {
            primary,
            escape_0f: Escape0F::build(),
            escape_0f38: Escape0F38::build(),
            escape_0f3a: Escape0F3A::build(),
        }
    }

    fn build_primary() -> Vec<OpcodeEntry> {
        let mut t: Vec<OpcodeEntry> = Vec::with_capacity(256);

        // 0x00–0x05  ADD
        t.push(OpcodeEntry::new(
            0x00,
            "add",
            InstrFormat::MR,
            PrefixHandler::None,
            "Add r8 to r/m8",
        ));
        t.push(OpcodeEntry::new(
            0x01,
            "add",
            InstrFormat::MR,
            PrefixHandler::None,
            "Add r16/32/64 to r/m",
        ));
        t.push(OpcodeEntry::new(
            0x02,
            "add",
            InstrFormat::RM,
            PrefixHandler::None,
            "Add r/m8 to r8",
        ));
        t.push(OpcodeEntry::new(
            0x03,
            "add",
            InstrFormat::RM,
            PrefixHandler::None,
            "Add r/m to r16/32/64",
        ));
        t.push(OpcodeEntry::new(
            0x04,
            "add",
            InstrFormat::I8,
            PrefixHandler::None,
            "Add imm8 to AL",
        ));
        t.push(OpcodeEntry::new(
            0x05,
            "add",
            InstrFormat::I32,
            PrefixHandler::None,
            "Add imm32 to rAX",
        ));

        // 0x06–0x07 PUSH/POP ES (invalid in 64-bit)
        t.push(
            OpcodeEntry::new(
                0x06,
                "push es",
                InstrFormat::ZO,
                PrefixHandler::None,
                "Push ES (invalid 64-bit)",
            )
            .faults(),
        );
        t.push(
            OpcodeEntry::new(
                0x07,
                "pop es",
                InstrFormat::ZO,
                PrefixHandler::None,
                "Pop ES (invalid 64-bit)",
            )
            .faults(),
        );

        // 0x08–0x0D OR
        t.push(OpcodeEntry::new(
            0x08,
            "or",
            InstrFormat::MR,
            PrefixHandler::None,
            "OR r8 into r/m8",
        ));
        t.push(OpcodeEntry::new(
            0x09,
            "or",
            InstrFormat::MR,
            PrefixHandler::None,
            "OR r into r/m",
        ));
        t.push(OpcodeEntry::new(
            0x0A,
            "or",
            InstrFormat::RM,
            PrefixHandler::None,
            "OR r/m8 into r8",
        ));
        t.push(OpcodeEntry::new(
            0x0B,
            "or",
            InstrFormat::RM,
            PrefixHandler::None,
            "OR r/m into r",
        ));
        t.push(OpcodeEntry::new(
            0x0C,
            "or",
            InstrFormat::I8,
            PrefixHandler::None,
            "OR imm8 with AL",
        ));
        t.push(OpcodeEntry::new(
            0x0D,
            "or",
            InstrFormat::I32,
            PrefixHandler::None,
            "OR imm32 with rAX",
        ));

        // 0x0F escape
        t.push(OpcodeEntry::new(
            0x0F,
            "esc0f",
            InstrFormat::ZO,
            PrefixHandler::None,
            "Two-byte escape",
        ));

        // 0x10–0x15 ADC
        t.push(OpcodeEntry::new(
            0x10,
            "adc",
            InstrFormat::MR,
            PrefixHandler::None,
            "ADC r8 to r/m8",
        ));
        t.push(OpcodeEntry::new(
            0x11,
            "adc",
            InstrFormat::MR,
            PrefixHandler::None,
            "ADC r to r/m",
        ));
        t.push(OpcodeEntry::new(
            0x12,
            "adc",
            InstrFormat::RM,
            PrefixHandler::None,
            "ADC r/m8 to r8",
        ));
        t.push(OpcodeEntry::new(
            0x13,
            "adc",
            InstrFormat::RM,
            PrefixHandler::None,
            "ADC r/m to r",
        ));
        t.push(OpcodeEntry::new(
            0x14,
            "adc",
            InstrFormat::I8,
            PrefixHandler::None,
            "ADC imm8 to AL",
        ));
        t.push(OpcodeEntry::new(
            0x15,
            "adc",
            InstrFormat::I32,
            PrefixHandler::None,
            "ADC imm32 to rAX",
        ));

        // 0x18–0x1D SBB
        t.push(OpcodeEntry::new(
            0x18,
            "sbb",
            InstrFormat::MR,
            PrefixHandler::None,
            "SBB r8 from r/m8",
        ));
        t.push(OpcodeEntry::new(
            0x19,
            "sbb",
            InstrFormat::MR,
            PrefixHandler::None,
            "SBB r from r/m",
        ));
        t.push(OpcodeEntry::new(
            0x1A,
            "sbb",
            InstrFormat::RM,
            PrefixHandler::None,
            "SBB r/m8 from r8",
        ));
        t.push(OpcodeEntry::new(
            0x1B,
            "sbb",
            InstrFormat::RM,
            PrefixHandler::None,
            "SBB r/m from r",
        ));
        t.push(OpcodeEntry::new(
            0x1C,
            "sbb",
            InstrFormat::I8,
            PrefixHandler::None,
            "SBB imm8 from AL",
        ));
        t.push(OpcodeEntry::new(
            0x1D,
            "sbb",
            InstrFormat::I32,
            PrefixHandler::None,
            "SBB imm32 from rAX",
        ));

        // 0x20–0x25 AND
        t.push(OpcodeEntry::new(
            0x20,
            "and",
            InstrFormat::MR,
            PrefixHandler::None,
            "AND r8 with r/m8",
        ));
        t.push(OpcodeEntry::new(
            0x21,
            "and",
            InstrFormat::MR,
            PrefixHandler::None,
            "AND r with r/m",
        ));
        t.push(OpcodeEntry::new(
            0x22,
            "and",
            InstrFormat::RM,
            PrefixHandler::None,
            "AND r/m8 with r8",
        ));
        t.push(OpcodeEntry::new(
            0x23,
            "and",
            InstrFormat::RM,
            PrefixHandler::None,
            "AND r/m with r",
        ));
        t.push(OpcodeEntry::new(
            0x24,
            "and",
            InstrFormat::I8,
            PrefixHandler::None,
            "AND imm8 with AL",
        ));
        t.push(OpcodeEntry::new(
            0x25,
            "and",
            InstrFormat::I32,
            PrefixHandler::None,
            "AND imm32 with rAX",
        ));
        t.push(OpcodeEntry::new(
            0x26,
            "es:",
            InstrFormat::ZO,
            PrefixHandler::None,
            "ES segment override prefix",
        ));
        t.push(
            OpcodeEntry::new(
                0x27,
                "daa",
                InstrFormat::ZO,
                PrefixHandler::None,
                "Decimal adjust AL after addition (invalid 64-bit)",
            )
            .faults(),
        );

        // 0x28–0x2D SUB
        t.push(OpcodeEntry::new(
            0x28,
            "sub",
            InstrFormat::MR,
            PrefixHandler::None,
            "SUB r8 from r/m8",
        ));
        t.push(OpcodeEntry::new(
            0x29,
            "sub",
            InstrFormat::MR,
            PrefixHandler::None,
            "SUB r from r/m",
        ));
        t.push(OpcodeEntry::new(
            0x2A,
            "sub",
            InstrFormat::RM,
            PrefixHandler::None,
            "SUB r/m8 from r8",
        ));
        t.push(OpcodeEntry::new(
            0x2B,
            "sub",
            InstrFormat::RM,
            PrefixHandler::None,
            "SUB r/m from r",
        ));
        t.push(OpcodeEntry::new(
            0x2C,
            "sub",
            InstrFormat::I8,
            PrefixHandler::None,
            "SUB imm8 from AL",
        ));
        t.push(OpcodeEntry::new(
            0x2D,
            "sub",
            InstrFormat::I32,
            PrefixHandler::None,
            "SUB imm32 from rAX",
        ));

        // 0x30–0x35 XOR
        t.push(OpcodeEntry::new(
            0x30,
            "xor",
            InstrFormat::MR,
            PrefixHandler::None,
            "XOR r8 with r/m8",
        ));
        t.push(OpcodeEntry::new(
            0x31,
            "xor",
            InstrFormat::MR,
            PrefixHandler::None,
            "XOR r with r/m",
        ));
        t.push(OpcodeEntry::new(
            0x32,
            "xor",
            InstrFormat::RM,
            PrefixHandler::None,
            "XOR r/m8 with r8",
        ));
        t.push(OpcodeEntry::new(
            0x33,
            "xor",
            InstrFormat::RM,
            PrefixHandler::None,
            "XOR r/m with r",
        ));
        t.push(OpcodeEntry::new(
            0x34,
            "xor",
            InstrFormat::I8,
            PrefixHandler::None,
            "XOR imm8 with AL",
        ));
        t.push(OpcodeEntry::new(
            0x35,
            "xor",
            InstrFormat::I32,
            PrefixHandler::None,
            "XOR imm32 with rAX",
        ));

        // 0x38–0x3D CMP
        t.push(OpcodeEntry::new(
            0x38,
            "cmp",
            InstrFormat::MR,
            PrefixHandler::None,
            "CMP r8 with r/m8",
        ));
        t.push(OpcodeEntry::new(
            0x39,
            "cmp",
            InstrFormat::MR,
            PrefixHandler::None,
            "CMP r with r/m",
        ));
        t.push(OpcodeEntry::new(
            0x3A,
            "cmp",
            InstrFormat::RM,
            PrefixHandler::None,
            "CMP r/m8 with r8",
        ));
        t.push(OpcodeEntry::new(
            0x3B,
            "cmp",
            InstrFormat::RM,
            PrefixHandler::None,
            "CMP r/m with r",
        ));
        t.push(OpcodeEntry::new(
            0x3C,
            "cmp",
            InstrFormat::I8,
            PrefixHandler::None,
            "CMP imm8 with AL",
        ));
        t.push(OpcodeEntry::new(
            0x3D,
            "cmp",
            InstrFormat::I32,
            PrefixHandler::None,
            "CMP imm32 with rAX",
        ));

        // 0x40–0x4F REX prefixes in 64-bit / INC/DEC in 32-bit
        for i in 0x40u8..=0x4F {
            t.push(OpcodeEntry::new(
                i,
                "rex",
                InstrFormat::ZO,
                PrefixHandler::RexW,
                "REX prefix byte",
            ));
        }

        // 0x50–0x57 PUSH rAX..rDI
        for i in 0u8..8 {
            t.push(OpcodeEntry::new(
                0x50 + i,
                "push",
                InstrFormat::O,
                PrefixHandler::None,
                "Push register",
            ));
        }
        // 0x58–0x5F POP rAX..rDI
        for i in 0u8..8 {
            t.push(OpcodeEntry::new(
                0x58 + i,
                "pop",
                InstrFormat::O,
                PrefixHandler::None,
                "Pop register",
            ));
        }

        // 0x60–0x63
        t.push(
            OpcodeEntry::new(
                0x60,
                "pusha",
                InstrFormat::ZO,
                PrefixHandler::None,
                "Push all (invalid 64-bit)",
            )
            .faults(),
        );
        t.push(
            OpcodeEntry::new(
                0x61,
                "popa",
                InstrFormat::ZO,
                PrefixHandler::None,
                "Pop all (invalid 64-bit)",
            )
            .faults(),
        );
        t.push(
            OpcodeEntry::new(
                0x62,
                "bound",
                InstrFormat::RM,
                PrefixHandler::None,
                "Check array index (invalid 64-bit)",
            )
            .faults(),
        );
        t.push(OpcodeEntry::new(
            0x63,
            "movsxd",
            InstrFormat::RM,
            PrefixHandler::RexW,
            "Move with sign-extension dword to qword",
        ));

        // 0x64–0x67 segment / address-size overrides
        t.push(OpcodeEntry::new(
            0x64,
            "fs:",
            InstrFormat::ZO,
            PrefixHandler::None,
            "FS segment override",
        ));
        t.push(OpcodeEntry::new(
            0x65,
            "gs:",
            InstrFormat::ZO,
            PrefixHandler::None,
            "GS segment override",
        ));
        t.push(OpcodeEntry::new(
            0x66,
            "66h:",
            InstrFormat::ZO,
            PrefixHandler::None,
            "Operand-size override",
        ));
        t.push(OpcodeEntry::new(
            0x67,
            "67h:",
            InstrFormat::ZO,
            PrefixHandler::None,
            "Address-size override",
        ));

        // 0x68–0x6B
        t.push(OpcodeEntry::new(
            0x68,
            "push",
            InstrFormat::I32,
            PrefixHandler::None,
            "Push imm32",
        ));
        t.push(OpcodeEntry::new(
            0x69,
            "imul",
            InstrFormat::RMI32,
            PrefixHandler::None,
            "Signed multiply r/m by imm32",
        ));
        t.push(OpcodeEntry::new(
            0x6A,
            "push",
            InstrFormat::I8,
            PrefixHandler::None,
            "Push imm8 sign-extended",
        ));
        t.push(OpcodeEntry::new(
            0x6B,
            "imul",
            InstrFormat::RMI8,
            PrefixHandler::None,
            "Signed multiply r/m by imm8",
        ));

        // 0x6C–0x6F string I/O
        t.push(OpcodeEntry::new(
            0x6C,
            "insb",
            InstrFormat::ZO,
            PrefixHandler::None,
            "Input byte from port DX into ES:rDI",
        ));
        t.push(OpcodeEntry::new(
            0x6D,
            "insw/d",
            InstrFormat::ZO,
            PrefixHandler::None,
            "Input word/dword from DX into ES:rDI",
        ));
        t.push(OpcodeEntry::new(
            0x6E,
            "outsb",
            InstrFormat::ZO,
            PrefixHandler::None,
            "Output byte from DS:rSI to port DX",
        ));
        t.push(OpcodeEntry::new(
            0x6F,
            "outsw/d",
            InstrFormat::ZO,
            PrefixHandler::None,
            "Output word/dword from DS:rSI to DX",
        ));

        // 0x70–0x7F short Jcc
        for (i, mn) in [
            "jo", "jno", "jb", "jae", "je", "jne", "jbe", "ja", "js", "jns", "jp", "jnp", "jl",
            "jge", "jle", "jg",
        ]
        .iter()
        .enumerate()
        {
            t.push(OpcodeEntry::new(
                0x70 + i as u8,
                mn,
                InstrFormat::D8,
                PrefixHandler::None,
                "Conditional jump short",
            ));
        }

        // 0x80–0x83 Group 1
        for (i, imm_fmt) in [
            (0x80u8, InstrFormat::MI8),
            (0x81, InstrFormat::MI32),
            (0x82, InstrFormat::MI8),
            (0x83, InstrFormat::MI8),
        ] {
            t.push(
                OpcodeEntry::new(i, "grp1", imm_fmt, PrefixHandler::None, "Group 1")
                    .with_group(OpcodeGroup::Group1),
            );
        }

        // 0x84–0x85 TEST
        t.push(OpcodeEntry::new(
            0x84,
            "test",
            InstrFormat::MR,
            PrefixHandler::None,
            "AND r8 with r/m8 (flags only)",
        ));
        t.push(OpcodeEntry::new(
            0x85,
            "test",
            InstrFormat::MR,
            PrefixHandler::None,
            "AND r with r/m (flags only)",
        ));

        // 0x86–0x87 XCHG
        t.push(OpcodeEntry::new(
            0x86,
            "xchg",
            InstrFormat::MR,
            PrefixHandler::None,
            "Exchange r8 and r/m8",
        ));
        t.push(OpcodeEntry::new(
            0x87,
            "xchg",
            InstrFormat::MR,
            PrefixHandler::None,
            "Exchange r and r/m",
        ));

        // 0x88–0x8B MOV
        t.push(OpcodeEntry::new(
            0x88,
            "mov",
            InstrFormat::MR,
            PrefixHandler::None,
            "Move r8 to r/m8",
        ));
        t.push(OpcodeEntry::new(
            0x89,
            "mov",
            InstrFormat::MR,
            PrefixHandler::None,
            "Move r to r/m",
        ));
        t.push(OpcodeEntry::new(
            0x8A,
            "mov",
            InstrFormat::RM,
            PrefixHandler::None,
            "Move r/m8 to r8",
        ));
        t.push(OpcodeEntry::new(
            0x8B,
            "mov",
            InstrFormat::RM,
            PrefixHandler::None,
            "Move r/m to r",
        ));
        t.push(OpcodeEntry::new(
            0x8C,
            "mov",
            InstrFormat::MR,
            PrefixHandler::None,
            "Move segment reg to r/m",
        ));
        t.push(OpcodeEntry::new(
            0x8D,
            "lea",
            InstrFormat::RM,
            PrefixHandler::None,
            "Load effective address",
        ));
        t.push(OpcodeEntry::new(
            0x8E,
            "mov",
            InstrFormat::RM,
            PrefixHandler::None,
            "Move r/m to segment reg",
        ));
        t.push(
            OpcodeEntry::new(
                0x8F,
                "pop",
                InstrFormat::M,
                PrefixHandler::None,
                "Pop r/m to stack",
            )
            .with_group(OpcodeGroup::Group1A),
        );

        // 0x90 NOP / XCHG rAX, rAX
        t.push(OpcodeEntry::new(
            0x90,
            "nop",
            InstrFormat::ZO,
            PrefixHandler::None,
            "No operation",
        ));
        for i in 1u8..8 {
            t.push(OpcodeEntry::new(
                0x90 + i,
                "xchg",
                InstrFormat::O,
                PrefixHandler::None,
                "Exchange rAX with register",
            ));
        }

        // 0x98–0x9F
        t.push(OpcodeEntry::new(
            0x98,
            "cbw/cwde/cdqe",
            InstrFormat::ZO,
            PrefixHandler::None,
            "Convert byte to word / word to dword / dword to qword",
        ));
        t.push(OpcodeEntry::new(
            0x99,
            "cwd/cdq/cqo",
            InstrFormat::ZO,
            PrefixHandler::None,
            "Convert word to dword / dword to qword",
        ));
        t.push(
            OpcodeEntry::new(
                0x9A,
                "callf",
                InstrFormat::FarPtr,
                PrefixHandler::None,
                "Call far (invalid 64-bit)",
            )
            .faults(),
        );
        t.push(OpcodeEntry::new(
            0x9B,
            "fwait",
            InstrFormat::ZO,
            PrefixHandler::None,
            "Wait for FPU",
        ));
        t.push(OpcodeEntry::new(
            0x9C,
            "pushf",
            InstrFormat::ZO,
            PrefixHandler::None,
            "Push FLAGS/EFLAGS/RFLAGS",
        ));
        t.push(OpcodeEntry::new(
            0x9D,
            "popf",
            InstrFormat::ZO,
            PrefixHandler::None,
            "Pop FLAGS/EFLAGS/RFLAGS",
        ));
        t.push(OpcodeEntry::new(
            0x9E,
            "sahf",
            InstrFormat::ZO,
            PrefixHandler::None,
            "Store AH into FLAGS",
        ));
        t.push(OpcodeEntry::new(
            0x9F,
            "lahf",
            InstrFormat::ZO,
            PrefixHandler::None,
            "Load FLAGS into AH",
        ));

        // 0xA0–0xA3 MOV accumulator ↔ memory
        t.push(OpcodeEntry::new(
            0xA0,
            "mov",
            InstrFormat::MemDirect,
            PrefixHandler::None,
            "Move AL from moffs8",
        ));
        t.push(OpcodeEntry::new(
            0xA1,
            "mov",
            InstrFormat::MemDirect,
            PrefixHandler::None,
            "Move rAX from moffs",
        ));
        t.push(OpcodeEntry::new(
            0xA2,
            "mov",
            InstrFormat::MemDirect,
            PrefixHandler::None,
            "Move AL to moffs8",
        ));
        t.push(OpcodeEntry::new(
            0xA3,
            "mov",
            InstrFormat::MemDirect,
            PrefixHandler::None,
            "Move rAX to moffs",
        ));

        // 0xA4–0xA7 string ops
        t.push(OpcodeEntry::new(
            0xA4,
            "movsb",
            InstrFormat::ZO,
            PrefixHandler::None,
            "Move data from string to string (byte)",
        ));
        t.push(OpcodeEntry::new(
            0xA5,
            "movsw/d/q",
            InstrFormat::ZO,
            PrefixHandler::None,
            "Move data from string to string",
        ));
        t.push(OpcodeEntry::new(
            0xA6,
            "cmpsb",
            InstrFormat::ZO,
            PrefixHandler::None,
            "Compare string (byte)",
        ));
        t.push(OpcodeEntry::new(
            0xA7,
            "cmpsw/d/q",
            InstrFormat::ZO,
            PrefixHandler::None,
            "Compare string",
        ));

        // 0xA8–0xAB TEST/STOSB/STOSD/LODSB
        t.push(OpcodeEntry::new(
            0xA8,
            "test",
            InstrFormat::I8,
            PrefixHandler::None,
            "AND imm8 with AL (flags only)",
        ));
        t.push(OpcodeEntry::new(
            0xA9,
            "test",
            InstrFormat::I32,
            PrefixHandler::None,
            "AND imm32 with rAX (flags only)",
        ));
        t.push(OpcodeEntry::new(
            0xAA,
            "stosb",
            InstrFormat::ZO,
            PrefixHandler::None,
            "Store AL to ES:rDI",
        ));
        t.push(OpcodeEntry::new(
            0xAB,
            "stosd/q",
            InstrFormat::ZO,
            PrefixHandler::None,
            "Store rAX to ES:rDI",
        ));
        t.push(OpcodeEntry::new(
            0xAC,
            "lodsb",
            InstrFormat::ZO,
            PrefixHandler::None,
            "Load AL from DS:rSI",
        ));
        t.push(OpcodeEntry::new(
            0xAD,
            "lodsd/q",
            InstrFormat::ZO,
            PrefixHandler::None,
            "Load rAX from DS:rSI",
        ));
        t.push(OpcodeEntry::new(
            0xAE,
            "scasb",
            InstrFormat::ZO,
            PrefixHandler::None,
            "Scan ES:rDI for AL",
        ));
        t.push(OpcodeEntry::new(
            0xAF,
            "scasd/q",
            InstrFormat::ZO,
            PrefixHandler::None,
            "Scan ES:rDI for rAX",
        ));

        // 0xB0–0xBF MOV immediate to register
        for i in 0u8..8 {
            t.push(OpcodeEntry::new(
                0xB0 + i,
                "mov",
                InstrFormat::OI,
                PrefixHandler::None,
                "Move imm8 to r8",
            ));
        }
        for i in 0u8..8 {
            t.push(OpcodeEntry::new(
                0xB8 + i,
                "mov",
                InstrFormat::OI,
                PrefixHandler::None,
                "Move imm16/32/64 to r",
            ));
        }

        // 0xC0–0xC1 Shift Group 2
        t.push(
            OpcodeEntry::new(
                0xC0,
                "grp2",
                InstrFormat::MI8,
                PrefixHandler::None,
                "Group 2 (byte, imm8)",
            )
            .with_group(OpcodeGroup::Group2),
        );
        t.push(
            OpcodeEntry::new(
                0xC1,
                "grp2",
                InstrFormat::MI8,
                PrefixHandler::None,
                "Group 2 (word/dword/qword, imm8)",
            )
            .with_group(OpcodeGroup::Group2),
        );

        // 0xC2–0xC3 RET
        t.push(OpcodeEntry::new(
            0xC2,
            "ret",
            InstrFormat::I16,
            PrefixHandler::None,
            "Near return and pop imm16 bytes",
        ));
        t.push(OpcodeEntry::new(
            0xC3,
            "ret",
            InstrFormat::ZO,
            PrefixHandler::None,
            "Near return",
        ));

        // 0xC4–0xC5 LES/LDS (VEX prefix in 64-bit)
        t.push(OpcodeEntry::new(
            0xC4,
            "vex3",
            InstrFormat::ZO,
            PrefixHandler::None,
            "3-byte VEX prefix",
        ));
        t.push(OpcodeEntry::new(
            0xC5,
            "vex2",
            InstrFormat::ZO,
            PrefixHandler::None,
            "2-byte VEX prefix",
        ));

        // 0xC6–0xC7 MOV Group 11
        t.push(
            OpcodeEntry::new(
                0xC6,
                "mov",
                InstrFormat::MI8,
                PrefixHandler::None,
                "Move imm8 to r/m8",
            )
            .with_group(OpcodeGroup::Group11),
        );
        t.push(
            OpcodeEntry::new(
                0xC7,
                "mov",
                InstrFormat::MI32,
                PrefixHandler::None,
                "Move imm32 to r/m",
            )
            .with_group(OpcodeGroup::Group11),
        );

        // 0xC8–0xCB
        t.push(OpcodeEntry::new(
            0xC8,
            "enter",
            InstrFormat::I16,
            PrefixHandler::None,
            "Make stack frame",
        ));
        t.push(OpcodeEntry::new(
            0xC9,
            "leave",
            InstrFormat::ZO,
            PrefixHandler::None,
            "High-level procedure exit",
        ));
        t.push(OpcodeEntry::new(
            0xCA,
            "retf",
            InstrFormat::I16,
            PrefixHandler::None,
            "Far return and pop imm16 bytes",
        ));
        t.push(OpcodeEntry::new(
            0xCB,
            "retf",
            InstrFormat::ZO,
            PrefixHandler::None,
            "Far return",
        ));

        // 0xCC–0xCF
        t.push(OpcodeEntry::new(
            0xCC,
            "int3",
            InstrFormat::ZO,
            PrefixHandler::None,
            "Call breakpoint exception",
        ));
        t.push(OpcodeEntry::new(
            0xCD,
            "int",
            InstrFormat::I8,
            PrefixHandler::None,
            "Call interrupt procedure",
        ));
        t.push(
            OpcodeEntry::new(
                0xCE,
                "into",
                InstrFormat::ZO,
                PrefixHandler::None,
                "Call overflow exception (invalid 64-bit)",
            )
            .faults(),
        );
        t.push(OpcodeEntry::new(
            0xCF,
            "iret",
            InstrFormat::ZO,
            PrefixHandler::None,
            "Interrupt return",
        ));

        // 0xD0–0xD3 Shift Group 2
        t.push(
            OpcodeEntry::new(
                0xD0,
                "grp2",
                InstrFormat::M1S,
                PrefixHandler::None,
                "Shift r/m8 by 1",
            )
            .with_group(OpcodeGroup::Group2),
        );
        t.push(
            OpcodeEntry::new(
                0xD1,
                "grp2",
                InstrFormat::M1S,
                PrefixHandler::None,
                "Shift r/m by 1",
            )
            .with_group(OpcodeGroup::Group2),
        );
        t.push(
            OpcodeEntry::new(
                0xD2,
                "grp2",
                InstrFormat::MC,
                PrefixHandler::None,
                "Shift r/m8 by CL",
            )
            .with_group(OpcodeGroup::Group2),
        );
        t.push(
            OpcodeEntry::new(
                0xD3,
                "grp2",
                InstrFormat::MC,
                PrefixHandler::None,
                "Shift r/m by CL",
            )
            .with_group(OpcodeGroup::Group2),
        );

        // 0xD4–0xD7 (invalid in 64-bit)
        t.push(
            OpcodeEntry::new(
                0xD4,
                "aam",
                InstrFormat::I8,
                PrefixHandler::None,
                "ASCII adjust AX after multiply (invalid 64-bit)",
            )
            .faults(),
        );
        t.push(
            OpcodeEntry::new(
                0xD5,
                "aad",
                InstrFormat::I8,
                PrefixHandler::None,
                "ASCII adjust AX before division (invalid 64-bit)",
            )
            .faults(),
        );
        t.push(OpcodeEntry::new(
            0xD7,
            "xlat",
            InstrFormat::ZO,
            PrefixHandler::None,
            "Table lookup translation",
        ));

        // 0xD8–0xDF x87 FPU (one representative per major opcode)
        for b in 0xD8u8..=0xDFu8 {
            t.push(OpcodeEntry::new(
                b,
                "x87",
                InstrFormat::M,
                PrefixHandler::None,
                "x87 FPU instruction",
            ));
        }

        // 0xE0–0xE3 LOOP/JCXZ
        t.push(OpcodeEntry::new(
            0xE0,
            "loopnz",
            InstrFormat::D8,
            PrefixHandler::None,
            "Loop if not zero",
        ));
        t.push(OpcodeEntry::new(
            0xE1,
            "loopz",
            InstrFormat::D8,
            PrefixHandler::None,
            "Loop if zero",
        ));
        t.push(OpcodeEntry::new(
            0xE2,
            "loop",
            InstrFormat::D8,
            PrefixHandler::None,
            "Loop",
        ));
        t.push(OpcodeEntry::new(
            0xE3,
            "jrcxz",
            InstrFormat::D8,
            PrefixHandler::None,
            "Jump short if rCX is zero",
        ));

        // 0xE4–0xE7 IN/OUT port
        t.push(OpcodeEntry::new(
            0xE4,
            "in",
            InstrFormat::I8,
            PrefixHandler::None,
            "Input from port imm8 to AL",
        ));
        t.push(OpcodeEntry::new(
            0xE5,
            "in",
            InstrFormat::I8,
            PrefixHandler::None,
            "Input from port imm8 to rAX",
        ));
        t.push(OpcodeEntry::new(
            0xE6,
            "out",
            InstrFormat::I8,
            PrefixHandler::None,
            "Output AL to port imm8",
        ));
        t.push(OpcodeEntry::new(
            0xE7,
            "out",
            InstrFormat::I8,
            PrefixHandler::None,
            "Output rAX to port imm8",
        ));

        // 0xE8–0xEB branch
        t.push(OpcodeEntry::new(
            0xE8,
            "call",
            InstrFormat::D32,
            PrefixHandler::None,
            "Call near, relative",
        ));
        t.push(OpcodeEntry::new(
            0xE9,
            "jmp",
            InstrFormat::D32,
            PrefixHandler::None,
            "Jump near, relative, imm32",
        ));
        t.push(
            OpcodeEntry::new(
                0xEA,
                "jmpf",
                InstrFormat::FarPtr,
                PrefixHandler::None,
                "Jump far (invalid 64-bit)",
            )
            .faults(),
        );
        t.push(OpcodeEntry::new(
            0xEB,
            "jmp",
            InstrFormat::D8,
            PrefixHandler::None,
            "Jump short, imm8",
        ));

        // 0xEC–0xEF IN/OUT DX
        t.push(OpcodeEntry::new(
            0xEC,
            "in",
            InstrFormat::ZO,
            PrefixHandler::None,
            "Input from port DX to AL",
        ));
        t.push(OpcodeEntry::new(
            0xED,
            "in",
            InstrFormat::ZO,
            PrefixHandler::None,
            "Input from port DX to rAX",
        ));
        t.push(OpcodeEntry::new(
            0xEE,
            "out",
            InstrFormat::ZO,
            PrefixHandler::None,
            "Output AL to port DX",
        ));
        t.push(OpcodeEntry::new(
            0xEF,
            "out",
            InstrFormat::ZO,
            PrefixHandler::None,
            "Output rAX to port DX",
        ));

        // 0xF0–0xF3 prefixes
        t.push(OpcodeEntry::new(
            0xF0,
            "lock:",
            InstrFormat::ZO,
            PrefixHandler::None,
            "LOCK prefix",
        ));
        t.push(OpcodeEntry::new(
            0xF1,
            "icebp",
            InstrFormat::ZO,
            PrefixHandler::None,
            "INT1 / ICEBP debug trap",
        ));
        t.push(OpcodeEntry::new(
            0xF2,
            "repnz:",
            InstrFormat::ZO,
            PrefixHandler::None,
            "REPNE/REPNZ prefix",
        ));
        t.push(OpcodeEntry::new(
            0xF3,
            "repz:",
            InstrFormat::ZO,
            PrefixHandler::None,
            "REP/REPE/REPZ prefix",
        ));

        // 0xF4–0xF7
        t.push(
            OpcodeEntry::new(0xF4, "hlt", InstrFormat::ZO, PrefixHandler::None, "Halt")
                .privileged(),
        );
        t.push(OpcodeEntry::new(
            0xF5,
            "cmc",
            InstrFormat::ZO,
            PrefixHandler::None,
            "Complement carry flag",
        ));
        t.push(
            OpcodeEntry::new(
                0xF6,
                "grp3",
                InstrFormat::M,
                PrefixHandler::None,
                "Group 3 (byte)",
            )
            .with_group(OpcodeGroup::Group3),
        );
        t.push(
            OpcodeEntry::new(
                0xF7,
                "grp3",
                InstrFormat::M,
                PrefixHandler::None,
                "Group 3 (word/dword/qword)",
            )
            .with_group(OpcodeGroup::Group3),
        );

        // 0xF8–0xFF
        t.push(OpcodeEntry::new(
            0xF8,
            "clc",
            InstrFormat::ZO,
            PrefixHandler::None,
            "Clear carry flag",
        ));
        t.push(OpcodeEntry::new(
            0xF9,
            "stc",
            InstrFormat::ZO,
            PrefixHandler::None,
            "Set carry flag",
        ));
        t.push(
            OpcodeEntry::new(
                0xFA,
                "cli",
                InstrFormat::ZO,
                PrefixHandler::None,
                "Clear interrupt flag",
            )
            .privileged(),
        );
        t.push(
            OpcodeEntry::new(
                0xFB,
                "sti",
                InstrFormat::ZO,
                PrefixHandler::None,
                "Set interrupt flag",
            )
            .privileged(),
        );
        t.push(OpcodeEntry::new(
            0xFC,
            "cld",
            InstrFormat::ZO,
            PrefixHandler::None,
            "Clear direction flag",
        ));
        t.push(OpcodeEntry::new(
            0xFD,
            "std",
            InstrFormat::ZO,
            PrefixHandler::None,
            "Set direction flag",
        ));
        t.push(
            OpcodeEntry::new(
                0xFE,
                "grp4",
                InstrFormat::M1,
                PrefixHandler::None,
                "Group 4 (INC/DEC r/m8)",
            )
            .with_group(OpcodeGroup::Group4),
        );
        t.push(
            OpcodeEntry::new(
                0xFF,
                "grp5",
                InstrFormat::M,
                PrefixHandler::None,
                "Group 5 (INC/CALL/JMP/PUSH)",
            )
            .with_group(OpcodeGroup::Group5),
        );

        t
    }

    /// Look up a primary opcode byte.
    #[must_use]
    pub fn lookup(&self, opcode: u8) -> Option<&OpcodeEntry> {
        self.primary.iter().find(|e| e.opcode == opcode)
    }

    /// Total number of entries in the primary table.
    #[must_use]
    pub const fn primary_count(&self) -> usize {
        self.primary.len()
    }

    /// Total entries across all sub-tables.
    #[must_use]
    pub const fn total_count(&self) -> usize {
        self.primary.len()
            + self.escape_0f.0.len()
            + self.escape_0f38.0.len()
            + self.escape_0f3a.0.len()
    }
}

// ---------------------------------------------------------------------------
// Missing format variant (used in Escape0F)
// ---------------------------------------------------------------------------
impl InstrFormat {
    /// MI with 8-bit immediate (alias for MRI8 without explicit src reg)
    pub const MRI8: InstrFormat = InstrFormat::RMI8;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn table() -> X86DecodeTable {
        X86DecodeTable::build()
    }

    // ── 1. Table builds without panic ───────────────────────────────────────
    #[test]
    fn test_build_no_panic() {
        let _ = table();
    }

    // ── 2. Primary table non-empty ──────────────────────────────────────────
    #[test]
    fn test_primary_non_empty() {
        assert!(
            table().primary_count() > 100,
            "expected >100 primary entries"
        );
    }

    // ── 3. Escape0F non-empty ───────────────────────────────────────────────
    #[test]
    fn test_escape_0f_non_empty() {
        assert!(!table().escape_0f.0.is_empty());
    }

    // ── 4. Escape0F38 non-empty ─────────────────────────────────────────────
    #[test]
    fn test_escape_0f38_non_empty() {
        assert!(!table().escape_0f38.0.is_empty());
    }

    // ── 5. Escape0F3A non-empty ─────────────────────────────────────────────
    #[test]
    fn test_escape_0f3a_non_empty() {
        assert!(!table().escape_0f3a.0.is_empty());
    }

    // ── 6. Total count > 300 ────────────────────────────────────────────────
    #[test]
    fn test_total_count() {
        assert!(table().total_count() > 300, "expected >300 total entries");
    }

    // ── 7. NOP at 0x90 ──────────────────────────────────────────────────────
    #[test]
    fn test_lookup_nop() {
        let t = table();
        let e = t.lookup(0x90).expect("0x90 must exist");
        assert_eq!(e.mnemonic, "nop");
    }

    // ── 8. RET at 0xC3 ──────────────────────────────────────────────────────
    #[test]
    fn test_lookup_ret() {
        let t = table();
        let e = t.lookup(0xC3).expect("0xC3 must exist");
        assert_eq!(e.mnemonic, "ret");
        assert!(!e.privileged);
    }

    // ── 9. CALL at 0xE8 ─────────────────────────────────────────────────────
    #[test]
    fn test_lookup_call() {
        let t = table();
        let e = t.lookup(0xE8).unwrap();
        assert_eq!(e.mnemonic, "call");
        assert!(e.is_branch());
    }

    // ── 10. JMP short 0xEB is a branch ──────────────────────────────────────
    #[test]
    fn test_lookup_jmp_short() {
        let t = table();
        let e = t.lookup(0xEB).unwrap();
        assert_eq!(e.mnemonic, "jmp");
        assert!(e.is_branch());
        assert_eq!(e.format, InstrFormat::D8);
    }

    // ── 11. HLT is privileged ───────────────────────────────────────────────
    #[test]
    fn test_lookup_hlt_privileged() {
        let t = table();
        let e = t.lookup(0xF4).unwrap();
        assert!(e.privileged);
    }

    // ── 12. UD2 in 0F table faults ──────────────────────────────────────────
    #[test]
    fn test_0f_ud2_faults() {
        let t = table();
        let e = t.escape_0f.lookup(0x0B, PrefixHandler::None).unwrap();
        assert!(e.may_fault);
    }

    // ── 13. SYSCALL in 0F table ─────────────────────────────────────────────
    #[test]
    fn test_0f_syscall() {
        let t = table();
        let e = t.escape_0f.lookup(0x05, PrefixHandler::None).unwrap();
        assert_eq!(e.mnemonic, "syscall");
    }

    // ── 14. MOV at 0x89 ─────────────────────────────────────────────────────
    #[test]
    fn test_lookup_mov_89() {
        let t = table();
        let e = t.lookup(0x89).unwrap();
        assert_eq!(e.mnemonic, "mov");
        assert_eq!(e.format, InstrFormat::MR);
        assert!(e.format.has_modrm());
    }

    // ── 15. InstrFormat has_modrm ───────────────────────────────────────────
    #[test]
    fn test_instr_format_has_modrm() {
        assert!(InstrFormat::MR.has_modrm());
        assert!(InstrFormat::RM.has_modrm());
        assert!(!InstrFormat::ZO.has_modrm());
        assert!(!InstrFormat::D8.has_modrm());
        assert!(!InstrFormat::I8.has_modrm());
    }

    // ── 16. InstrFormat min_imm_bytes ───────────────────────────────────────
    #[test]
    fn test_instr_format_min_imm_bytes() {
        assert_eq!(InstrFormat::I8.min_imm_bytes(), 1);
        assert_eq!(InstrFormat::I16.min_imm_bytes(), 2);
        assert_eq!(InstrFormat::I32.min_imm_bytes(), 4);
        assert_eq!(InstrFormat::ZO.min_imm_bytes(), 0);
        assert_eq!(InstrFormat::MR.min_imm_bytes(), 0);
    }

    // ── 17. PrefixHandler display ────────────────────────────────────────────
    #[test]
    fn test_prefix_display() {
        assert_eq!(format!("{}", PrefixHandler::None), "");
        assert_eq!(format!("{}", PrefixHandler::P66), "66 ");
        assert_eq!(format!("{}", PrefixHandler::PF2), "F2 ");
        assert_eq!(format!("{}", PrefixHandler::RexW), "REX.W ");
    }

    // ── 18. PUSH at 0x50 ────────────────────────────────────────────────────
    #[test]
    fn test_lookup_push() {
        let t = table();
        let e = t.lookup(0x50).unwrap();
        assert_eq!(e.mnemonic, "push");
    }

    // ── 19. Group 1 at 0x81 ─────────────────────────────────────────────────
    #[test]
    fn test_lookup_group1() {
        let t = table();
        let e = t.lookup(0x81).unwrap();
        assert_eq!(e.group, OpcodeGroup::Group1);
    }

    // ── 20. Group 5 at 0xFF ─────────────────────────────────────────────────
    #[test]
    fn test_lookup_group5() {
        let t = table();
        let e = t.lookup(0xFF).unwrap();
        assert_eq!(e.group, OpcodeGroup::Group5);
    }

    // ── 21. Short Jcc 0x70 ──────────────────────────────────────────────────
    #[test]
    fn test_lookup_jo() {
        let t = table();
        let e = t.lookup(0x70).unwrap();
        assert_eq!(e.mnemonic, "jo");
        assert!(e.is_branch());
    }

    // ── 22. Long Jcc in 0F table ────────────────────────────────────────────
    #[test]
    fn test_0f_long_jcc() {
        let t = table();
        // 0x84 = JE/JZ long
        let e = t.escape_0f.lookup(0x84, PrefixHandler::None).unwrap();
        assert_eq!(e.mnemonic, "je");
        assert!(e.is_branch());
    }

    // ── 23. MOVAPS in 0F table ──────────────────────────────────────────────
    #[test]
    fn test_0f_movaps() {
        let t = table();
        let e = t.escape_0f.lookup(0x28, PrefixHandler::None).unwrap();
        assert_eq!(e.mnemonic, "movaps");
    }

    // ── 24. MOVAPD (66 prefix) in 0F table ──────────────────────────────────
    #[test]
    fn test_0f_movapd() {
        let t = table();
        let e = t.escape_0f.lookup(0x28, PrefixHandler::P66).unwrap();
        assert_eq!(e.mnemonic, "movapd");
    }

    // ── 25. MOVSS (F3 prefix) in 0F table ───────────────────────────────────
    #[test]
    fn test_0f_movss() {
        let t = table();
        let e = t.escape_0f.lookup(0x10, PrefixHandler::PF3).unwrap();
        assert_eq!(e.mnemonic, "movss");
    }

    // ── 26. CRC32 in 0F38 table ─────────────────────────────────────────────
    #[test]
    fn test_0f38_crc32() {
        let t = table();
        let e = t.escape_0f38.lookup(0xF0, PrefixHandler::PF2).unwrap();
        assert_eq!(e.mnemonic, "crc32");
    }

    // ── 27. PCLMULQDQ in 0F3A table ─────────────────────────────────────────
    #[test]
    fn test_0f3a_pclmulqdq() {
        let t = table();
        let e = t.escape_0f3a.lookup(0x44, PrefixHandler::P66).unwrap();
        assert_eq!(e.mnemonic, "pclmulqdq");
    }

    // ── 28. AESKEYGENASSIST in 0F3A table ───────────────────────────────────
    #[test]
    fn test_0f3a_aeskeygenassist() {
        let t = table();
        let e = t.escape_0f3a.lookup(0xDF, PrefixHandler::P66).unwrap();
        assert_eq!(e.mnemonic, "aeskeygenassist");
    }

    // ── 29. RDTSC in 0F table ────────────────────────────────────────────────
    #[test]
    fn test_0f_rdtsc() {
        let t = table();
        let e = t.escape_0f.lookup(0x31, PrefixHandler::None).unwrap();
        assert_eq!(e.mnemonic, "rdtsc");
    }

    // ── 30. WRMSR is privileged ──────────────────────────────────────────────
    #[test]
    fn test_0f_wrmsr_privileged() {
        let t = table();
        let e = t.escape_0f.lookup(0x30, PrefixHandler::None).unwrap();
        assert!(e.privileged);
    }

    // ── 31. MOVZX at 0x0F B6 ────────────────────────────────────────────────
    #[test]
    fn test_0f_movzx() {
        let t = table();
        let e = t.escape_0f.lookup(0xB6, PrefixHandler::None).unwrap();
        assert_eq!(e.mnemonic, "movzx");
    }

    // ── 32. BSWAP 0F C8..CF ──────────────────────────────────────────────────
    #[test]
    fn test_0f_bswap() {
        let t = table();
        for b in 0xC8u8..=0xCF {
            let e = t.escape_0f.lookup(b, PrefixHandler::None).unwrap();
            assert_eq!(e.mnemonic, "bswap", "opcode {b:#x}");
        }
    }

    // ── 33. SETcc 0F 90..9F all present ─────────────────────────────────────
    #[test]
    fn test_0f_setcc() {
        let t = table();
        for b in 0x90u8..=0x9F {
            let e = t.escape_0f.lookup(b, PrefixHandler::None);
            assert!(e.is_some(), "setcc {b:#x} missing");
        }
    }

    // ── 34. CMOVcc 0F 40..4F ────────────────────────────────────────────────
    #[test]
    fn test_0f_cmovcc() {
        let t = table();
        for b in 0x40u8..=0x4F {
            let e = t.escape_0f.lookup(b, PrefixHandler::None);
            assert!(e.is_some(), "cmovcc {b:#x} missing");
        }
    }

    // ── 35. OpcodeEntry is_branch for JMP/CALL/RET ──────────────────────────
    #[test]
    fn test_opcode_entry_is_branch() {
        let jmp = OpcodeEntry::new(0xE9, "jmp", InstrFormat::D32, PrefixHandler::None, "");
        assert!(jmp.is_branch());
        let nop = OpcodeEntry::new(0x90, "nop", InstrFormat::ZO, PrefixHandler::None, "");
        assert!(!nop.is_branch());
    }

    // ── 36. OpcodeEntry accesses_memory ─────────────────────────────────────
    #[test]
    fn test_opcode_entry_accesses_memory() {
        let mov_mr = OpcodeEntry::new(0x89, "mov", InstrFormat::MR, PrefixHandler::None, "");
        assert!(mov_mr.accesses_memory());
        let nop = OpcodeEntry::new(0x90, "nop", InstrFormat::ZO, PrefixHandler::None, "");
        assert!(!nop.accesses_memory());
    }

    // ── 37. OpcodeGroup None vs Group1 ──────────────────────────────────────
    #[test]
    fn test_opcode_group_variants() {
        let e1 = OpcodeEntry::new(0x81, "grp1", InstrFormat::MI32, PrefixHandler::None, "")
            .with_group(OpcodeGroup::Group1);
        assert_eq!(e1.group, OpcodeGroup::Group1);
        let e2 = OpcodeEntry::new(0x90, "nop", InstrFormat::ZO, PrefixHandler::None, "");
        assert_eq!(e2.group, OpcodeGroup::None);
    }

    // ── 38. Escape0F lookup fallback to None prefix ──────────────────────────
    #[test]
    fn test_0f_lookup_fallback() {
        // MOVUPS at 0x10 has None prefix entry; looking up with P66 should fallback
        let t = table();
        // 0x10 with P66 → MOVUPD
        let e_p66 = t.escape_0f.lookup(0x10, PrefixHandler::P66);
        // Should find the P66 entry first
        assert!(e_p66.is_some());
        assert_eq!(e_p66.unwrap().mnemonic, "movupd");
    }

    // ── 39. LEA at 0x8D has ModRM ───────────────────────────────────────────
    #[test]
    fn test_lea_has_modrm() {
        let t = table();
        let e = t.lookup(0x8D).unwrap();
        assert_eq!(e.mnemonic, "lea");
        assert!(e.format.has_modrm());
    }

    // ── 40. CPUID in 0F table ────────────────────────────────────────────────
    #[test]
    fn test_0f_cpuid() {
        let t = table();
        let e = t.escape_0f.lookup(0xA2, PrefixHandler::None).unwrap();
        assert_eq!(e.mnemonic, "cpuid");
    }

    // ── 41. IMUL in 0F table ─────────────────────────────────────────────────
    #[test]
    fn test_0f_imul() {
        let t = table();
        let e = t.escape_0f.lookup(0xAF, PrefixHandler::None).unwrap();
        assert_eq!(e.mnemonic, "imul");
        assert!(e.format.has_modrm());
    }

    // ── 42. 0F38 PSHUFB entry ────────────────────────────────────────────────
    #[test]
    fn test_0f38_pshufb() {
        let t = table();
        let e = t.escape_0f38.lookup(0x00, PrefixHandler::P66).unwrap();
        assert_eq!(e.mnemonic, "pshufb");
    }

    // ── Additional tests ─────────────────────────────────────────────────────

    #[test]
    fn test_primary_contains_mov_88_to_8b() {
        let t = table();
        for op in [0x88u8, 0x89, 0x8A, 0x8B] {
            assert!(t.lookup(op).is_some(), "0x{op:02x} missing");
        }
    }

    #[test]
    fn test_primary_ret_cf_cb() {
        let t = table();
        // 0xCA = RETF imm16, 0xCB = RETF
        assert!(t.lookup(0xCA).is_some());
        assert!(t.lookup(0xCB).is_some());
    }

    #[test]
    fn test_primary_contains_push_pop_prefix() {
        let t = table();
        for op in [0x64u8, 0x65, 0x66, 0x67] {
            assert!(t.lookup(op).is_some(), "prefix {op:#04x} missing");
        }
    }

    #[test]
    fn test_instr_format_rvmr_has_modrm() {
        assert!(InstrFormat::RVMR.has_modrm());
    }

    #[test]
    fn test_instr_format_rvm_has_modrm() {
        assert!(InstrFormat::RVM.has_modrm());
    }

    #[test]
    fn test_opcode_entry_faults_flag() {
        let e = OpcodeEntry::new(0x0B, "ud2", InstrFormat::ZO, PrefixHandler::None, "").faults();
        assert!(e.may_fault);
    }

    #[test]
    fn test_opcode_entry_privileged_flag() {
        let e =
            OpcodeEntry::new(0xF4, "hlt", InstrFormat::ZO, PrefixHandler::None, "").privileged();
        assert!(e.privileged);
    }

    #[test]
    fn test_0f_shld_shrd() {
        let t = table();
        let shld = t.escape_0f.lookup(0xA4, PrefixHandler::None).unwrap();
        assert_eq!(shld.mnemonic, "shld");
        let shrd = t.escape_0f.lookup(0xAC, PrefixHandler::None).unwrap();
        assert_eq!(shrd.mnemonic, "shrd");
    }

    #[test]
    fn test_0f3a_roundss_roundsd() {
        let t = table();
        let rs = t.escape_0f3a.lookup(0x0A, PrefixHandler::P66).unwrap();
        assert_eq!(rs.mnemonic, "roundss");
        let rd = t.escape_0f3a.lookup(0x0B, PrefixHandler::P66).unwrap();
        assert_eq!(rd.mnemonic, "roundsd");
    }

    #[test]
    fn test_0f_xadd() {
        let t = table();
        let e = t.escape_0f.lookup(0xC0, PrefixHandler::None).unwrap();
        assert_eq!(e.mnemonic, "xadd");
    }

    #[test]
    fn test_0f38_aesni_entries() {
        let t = table();
        let aesimc = t.escape_0f38.lookup(0xDB, PrefixHandler::P66);
        assert!(aesimc.is_some(), "aesimc missing");
    }
}
