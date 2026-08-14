//! ELF relocation type tables and parsed relocation entries.
//!
//! Covers x86 (`EM_386`), x86-64 (`EM_X86_64`), ARM (`EM_ARM`), `AArch64`
//! (`EM_AARCH64`), MIPS (`EM_MIPS`), RISC-V (`EM_RISCV`), PowerPC (`EM_PPC`),
//! `PowerPC64` (`EM_PPC64`), and SPARC (`EM_SPARC` / `EM_SPARCV9`).

// ─────────────────────────────────────────────────────────────────────────────
// x86  (EM_386)
// ─────────────────────────────────────────────────────────────────────────────

/// Relocation types for the x86 (`EM_386`) architecture.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum X86Reloc {
    None = 0,
    Rel32 = 1, // (S + A - P)
    Abs32 = 2, // S + A
    Got32 = 3, // G + A
    Plt32 = 4, // L + A - P
    Copy = 5,
    GlobDat = 6,  // S
    JmpSlot = 7,  // S
    Relative = 8, // B + A
    GotOff = 9,   // S + A - GOT
    GotPc = 10,   // GOT + A - P
    Got32X = 43,
    TlsGd = 18,
    TlsLdm = 19,
    TlsDtpoff32 = 21,
    TlsDtpmod32 = 20,
    TlsIe32 = 23,
    TlsGottpoff = 24,
    TlsTpoff = 14,
    TlsTpoff32 = 25,
    /// Any type not covered above.
    Other(u32),
}

impl X86Reloc {
    /// Parse from raw `r_type` field.
    #[must_use]
    pub const fn from_raw(t: u32) -> Self {
        match t {
            0 => Self::None,
            1 => Self::Rel32,
            2 => Self::Abs32,
            3 => Self::Got32,
            4 => Self::Plt32,
            5 => Self::Copy,
            6 => Self::GlobDat,
            7 => Self::JmpSlot,
            8 => Self::Relative,
            9 => Self::GotOff,
            10 => Self::GotPc,
            14 => Self::TlsTpoff,
            18 => Self::TlsGd,
            19 => Self::TlsLdm,
            20 => Self::TlsDtpmod32,
            21 => Self::TlsDtpoff32,
            23 => Self::TlsIe32,
            24 => Self::TlsGottpoff,
            25 => Self::TlsTpoff32,
            43 => Self::Got32X,
            _ => Self::Other(t),
        }
    }

    /// Return the raw relocation type integer.
    #[must_use]
    pub const fn as_raw(self) -> u32 {
        match self {
            Self::None => 0,
            Self::Rel32 => 1,
            Self::Abs32 => 2,
            Self::Got32 => 3,
            Self::Plt32 => 4,
            Self::Copy => 5,
            Self::GlobDat => 6,
            Self::JmpSlot => 7,
            Self::Relative => 8,
            Self::GotOff => 9,
            Self::GotPc => 10,
            Self::TlsTpoff => 14,
            Self::TlsGd => 18,
            Self::TlsLdm => 19,
            Self::TlsDtpmod32 => 20,
            Self::TlsDtpoff32 => 21,
            Self::TlsIe32 => 23,
            Self::TlsGottpoff => 24,
            Self::TlsTpoff32 => 25,
            Self::Got32X => 43,
            Self::Other(n) => n,
        }
    }

    /// Return a human-readable name for this relocation type.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::None => "R_386_NONE",
            Self::Rel32 => "R_386_PC32",
            Self::Abs32 => "R_386_32",
            Self::Got32 => "R_386_GOT32",
            Self::Plt32 => "R_386_PLT32",
            Self::Copy => "R_386_COPY",
            Self::GlobDat => "R_386_GLOB_DAT",
            Self::JmpSlot => "R_386_JMP_SLOT",
            Self::Relative => "R_386_RELATIVE",
            Self::GotOff => "R_386_GOTOFF",
            Self::GotPc => "R_386_GOTPC",
            Self::TlsGd => "R_386_TLS_GD",
            Self::TlsLdm => "R_386_TLS_LDM",
            Self::TlsDtpmod32 => "R_386_TLS_DTPMOD32",
            Self::TlsDtpoff32 => "R_386_TLS_DTPOFF32",
            Self::TlsIe32 => "R_386_TLS_IE_32",
            Self::TlsGottpoff => "R_386_TLS_GOTDESC",
            Self::TlsTpoff => "R_386_TLS_TPOFF",
            Self::TlsTpoff32 => "R_386_TLS_TPOFF32",
            Self::Got32X => "R_386_GOT32X",
            Self::Other(_) => "R_386_<unknown>",
        }
    }

    /// Return `true` if this is a PLT-related relocation (dynamic linker lazy binding).
    #[must_use]
    pub const fn is_plt(self) -> bool {
        matches!(self, Self::Plt32 | Self::JmpSlot)
    }

    /// Return `true` if this is a copy relocation.
    #[must_use]
    pub const fn is_copy(self) -> bool {
        matches!(self, Self::Copy)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// x86-64  (EM_X86_64)
// ─────────────────────────────────────────────────────────────────────────────

/// Relocation types for the x86-64 (`EM_X86_64` / AMD64) architecture.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum X86_64Reloc {
    None,
    Abs64,
    Pc32,
    Got32,
    Plt32,
    Copy,
    GlobDat,
    JmpSlot,
    Relative,
    GotPcRel,
    Abs32,
    Abs32s,
    Abs16,
    Pc16,
    Abs8,
    Pc8,
    DtpMod64,
    DtpOff64,
    TpOff64,
    TlsGd,
    TlsLd,
    DtpOff32,
    GotTpOff,
    TpOff32,
    Pc64,
    GotOff64,
    GotPc32,
    Size32,
    Size64,
    GotPc32TlsDesc,
    TlsDescCall,
    TlsDesc,
    IRelative,
    Relative64,
    GotPcRelx,
    RexGotPcRelx,
    Other(u32),
}

impl X86_64Reloc {
    /// Parse from raw `r_type` field.
    #[must_use]
    pub const fn from_raw(t: u32) -> Self {
        match t {
            0 => Self::None,
            1 => Self::Abs64,
            2 => Self::Pc32,
            3 => Self::Got32,
            4 => Self::Plt32,
            5 => Self::Copy,
            6 => Self::GlobDat,
            7 => Self::JmpSlot,
            8 => Self::Relative,
            9 => Self::GotPcRel,
            10 => Self::Abs32,
            11 => Self::Abs32s,
            12 => Self::Abs16,
            13 => Self::Pc16,
            14 => Self::Abs8,
            15 => Self::Pc8,
            16 => Self::DtpMod64,
            17 => Self::DtpOff64,
            18 => Self::TpOff64,
            19 => Self::TlsGd,
            20 => Self::TlsLd,
            21 => Self::DtpOff32,
            22 => Self::GotTpOff,
            23 => Self::TpOff32,
            24 => Self::Pc64,
            25 => Self::GotOff64,
            26 => Self::GotPc32,
            32 => Self::Size32,
            33 => Self::Size64,
            34 => Self::GotPc32TlsDesc,
            35 => Self::TlsDescCall,
            36 => Self::TlsDesc,
            37 => Self::IRelative,
            38 => Self::Relative64,
            41 => Self::GotPcRelx,
            42 => Self::RexGotPcRelx,
            _ => Self::Other(t),
        }
    }

    /// Return the raw relocation type integer.
    #[must_use]
    pub const fn as_raw(self) -> u32 {
        match self {
            Self::None => 0,
            Self::Abs64 => 1,
            Self::Pc32 => 2,
            Self::Got32 => 3,
            Self::Plt32 => 4,
            Self::Copy => 5,
            Self::GlobDat => 6,
            Self::JmpSlot => 7,
            Self::Relative => 8,
            Self::GotPcRel => 9,
            Self::Abs32 => 10,
            Self::Abs32s => 11,
            Self::Abs16 => 12,
            Self::Pc16 => 13,
            Self::Abs8 => 14,
            Self::Pc8 => 15,
            Self::DtpMod64 => 16,
            Self::DtpOff64 => 17,
            Self::TpOff64 => 18,
            Self::TlsGd => 19,
            Self::TlsLd => 20,
            Self::DtpOff32 => 21,
            Self::GotTpOff => 22,
            Self::TpOff32 => 23,
            Self::Pc64 => 24,
            Self::GotOff64 => 25,
            Self::GotPc32 => 26,
            Self::Size32 => 32,
            Self::Size64 => 33,
            Self::GotPc32TlsDesc => 34,
            Self::TlsDescCall => 35,
            Self::TlsDesc => 36,
            Self::IRelative => 37,
            Self::Relative64 => 38,
            Self::GotPcRelx => 41,
            Self::RexGotPcRelx => 42,
            Self::Other(n) => n,
        }
    }

    /// Return a human-readable name for this relocation type.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::None => "R_X86_64_NONE",
            Self::Abs64 => "R_X86_64_64",
            Self::Pc32 => "R_X86_64_PC32",
            Self::Got32 => "R_X86_64_GOT32",
            Self::Plt32 => "R_X86_64_PLT32",
            Self::Copy => "R_X86_64_COPY",
            Self::GlobDat => "R_X86_64_GLOB_DAT",
            Self::JmpSlot => "R_X86_64_JUMP_SLOT",
            Self::Relative => "R_X86_64_RELATIVE",
            Self::GotPcRel => "R_X86_64_GOTPCREL",
            Self::Abs32 => "R_X86_64_32",
            Self::Abs32s => "R_X86_64_32S",
            Self::Abs16 => "R_X86_64_16",
            Self::Pc16 => "R_X86_64_PC16",
            Self::Abs8 => "R_X86_64_8",
            Self::Pc8 => "R_X86_64_PC8",
            Self::DtpMod64 => "R_X86_64_DTPMOD64",
            Self::DtpOff64 => "R_X86_64_DTPOFF64",
            Self::TpOff64 => "R_X86_64_TPOFF64",
            Self::TlsGd => "R_X86_64_TLSGD",
            Self::TlsLd => "R_X86_64_TLSLD",
            Self::DtpOff32 => "R_X86_64_DTPOFF32",
            Self::GotTpOff => "R_X86_64_GOTTPOFF",
            Self::TpOff32 => "R_X86_64_TPOFF32",
            Self::Pc64 => "R_X86_64_PC64",
            Self::GotOff64 => "R_X86_64_GOTOFF64",
            Self::GotPc32 => "R_X86_64_GOTPC32",
            Self::Size32 => "R_X86_64_SIZE32",
            Self::Size64 => "R_X86_64_SIZE64",
            Self::GotPc32TlsDesc => "R_X86_64_GOTPC32_TLSDESC",
            Self::TlsDescCall => "R_X86_64_TLSDESC_CALL",
            Self::TlsDesc => "R_X86_64_TLSDESC",
            Self::IRelative => "R_X86_64_IRELATIVE",
            Self::Relative64 => "R_X86_64_RELATIVE64",
            Self::GotPcRelx => "R_X86_64_GOTPCRELX",
            Self::RexGotPcRelx => "R_X86_64_REX_GOTPCRELX",
            Self::Other(_) => "R_X86_64_<unknown>",
        }
    }

    /// Return `true` for dynamic-linker PLT slot types.
    #[must_use]
    pub const fn is_jmp_slot(self) -> bool {
        matches!(self, Self::JmpSlot)
    }

    /// Return `true` for IFUNC (indirect function) relocation.
    #[must_use]
    pub const fn is_ifunc(self) -> bool {
        matches!(self, Self::IRelative)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ARM  (EM_ARM)
// ─────────────────────────────────────────────────────────────────────────────

/// Relocation types for the ARM (`EM_ARM`, 32-bit) architecture.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ArmReloc {
    None,
    Abs32,
    Rel32,
    LdrPcG0,
    Abs16,
    Abs12,
    ThmbAbs5,
    Abs8,
    Sbrel32,
    ThmbCall,
    ThmbPc8,
    BrelExpd,
    ThmbJump11,
    ThmbJump8,
    Call,
    Jump24,
    ThmbJump24,
    Target1,
    Copy,
    GlobDat,
    JmpSlot,
    Relative,
    GotOff32,
    BasePrel,
    GotBrel,
    CallPl,
    Plt32,
    TlsDescSeq,
    TlsGd32,
    TlsLdm32,
    TlsLdo32,
    TlsIe32,
    TlsLe32,
    IRelative,
    Other(u32),
}

impl ArmReloc {
    /// Parse from raw `r_type`.
    #[must_use]
    pub const fn from_raw(t: u32) -> Self {
        match t {
            0 => Self::None,
            2 => Self::Abs32,
            3 => Self::Rel32,
            4 => Self::LdrPcG0,
            5 => Self::Abs16,
            6 => Self::Abs12,
            7 => Self::ThmbAbs5,
            8 => Self::Abs8,
            9 => Self::Sbrel32,
            10 => Self::ThmbCall,
            11 => Self::ThmbPc8,
            14 => Self::Call,
            15 => Self::Jump24,
            16 => Self::ThmbJump24,
            20 => Self::Copy,
            21 => Self::GlobDat,
            22 => Self::JmpSlot,
            23 => Self::Relative,
            24 => Self::GotOff32,
            25 => Self::BasePrel,
            26 => Self::GotBrel,
            28 => Self::Plt32,
            88 => Self::TlsGd32,
            89 => Self::TlsLdm32,
            90 => Self::TlsLdo32,
            92 => Self::TlsIe32,
            93 => Self::TlsLe32,
            160 => Self::IRelative,
            _ => Self::Other(t),
        }
    }

    /// Return a human-readable name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::None => "R_ARM_NONE",
            Self::Abs32 => "R_ARM_ABS32",
            Self::Rel32 => "R_ARM_REL32",
            Self::Abs16 => "R_ARM_ABS16",
            Self::Abs12 => "R_ARM_ABS12",
            Self::Abs8 => "R_ARM_ABS8",
            Self::Call => "R_ARM_CALL",
            Self::Jump24 => "R_ARM_JUMP24",
            Self::Copy => "R_ARM_COPY",
            Self::GlobDat => "R_ARM_GLOB_DAT",
            Self::JmpSlot => "R_ARM_JUMP_SLOT",
            Self::Relative => "R_ARM_RELATIVE",
            Self::GotOff32 => "R_ARM_GOTOFF32",
            Self::Plt32 => "R_ARM_PLT32",
            Self::TlsGd32 => "R_ARM_TLS_GD32",
            Self::TlsLdm32 => "R_ARM_TLS_LDM32",
            Self::TlsLdo32 => "R_ARM_TLS_LDO32",
            Self::TlsIe32 => "R_ARM_TLS_IE32",
            Self::TlsLe32 => "R_ARM_TLS_LE32",
            Self::IRelative => "R_ARM_IRELATIVE",
            Self::ThmbCall => "R_ARM_THM_CALL",
            Self::ThmbJump24 => "R_ARM_THM_JUMP24",
            _ => "R_ARM_<unknown>",
        }
    }

    /// Return `true` for the Thumb-mode call relocs.
    #[must_use]
    pub const fn is_thumb(self) -> bool {
        matches!(
            self,
            Self::ThmbCall | Self::ThmbJump24 | Self::ThmbAbs5 | Self::ThmbPc8
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AArch64  (EM_AARCH64)
// ─────────────────────────────────────────────────────────────────────────────

/// Relocation types for the `AArch64` (`EM_AARCH64`) architecture.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Aarch64Reloc {
    None,
    Abs64,
    Abs32,
    Abs16,
    Prel64,
    Prel32,
    Prel16,
    MovwUAbsG0,
    MovwUAbsG0Nc,
    MovwUAbsG1,
    MovwUAbsG1Nc,
    MovwUAbsG2,
    MovwUAbsG2Nc,
    MovwUAbsG3,
    AdrPrelPg21,
    AddAbsLo12Nc,
    LdstAbsLo12Nc,
    Ld64GotLo12Nc,
    GotRel64,
    GotRel32,
    Call26,
    Jump26,
    Copy,
    GlobDat,
    JmpSlot,
    Relative,
    TlsDtpmod64,
    TlsDtprel64,
    TlsTprel64,
    TlsDtpmod32,
    TlsDtprel32,
    TlsTprel32,
    TlsDescAdrPrelPg21,
    TlsDescAddAbsLo12Nc,
    TlsDescCall,
    TlsDesc,
    IRelative,
    Other(u32),
}

impl Aarch64Reloc {
    /// Parse from raw `r_type`.
    #[must_use]
    pub const fn from_raw(t: u32) -> Self {
        match t {
            0 => Self::None,
            257 => Self::Abs64,
            258 => Self::Abs32,
            259 => Self::Abs16,
            260 => Self::Prel64,
            261 => Self::Prel32,
            262 => Self::Prel16,
            263 => Self::MovwUAbsG0,
            264 => Self::MovwUAbsG0Nc,
            265 => Self::MovwUAbsG1,
            266 => Self::MovwUAbsG1Nc,
            267 => Self::MovwUAbsG2,
            268 => Self::MovwUAbsG2Nc,
            269 => Self::MovwUAbsG3,
            275 => Self::AdrPrelPg21,
            277 => Self::AddAbsLo12Nc,
            278 => Self::LdstAbsLo12Nc,
            309 => Self::Ld64GotLo12Nc,
            1024 => Self::Copy,
            1025 => Self::GlobDat,
            1026 => Self::JmpSlot,
            1027 => Self::Relative,
            1028 => Self::TlsDtpmod64,
            1029 => Self::TlsDtprel64,
            1030 => Self::TlsTprel64,
            1036 => Self::TlsDesc,
            1040 => Self::IRelative,
            283 => Self::Call26,
            282 => Self::Jump26,
            _ => Self::Other(t),
        }
    }

    /// Return a human-readable name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::None => "R_AARCH64_NONE",
            Self::Abs64 => "R_AARCH64_ABS64",
            Self::Abs32 => "R_AARCH64_ABS32",
            Self::Prel64 => "R_AARCH64_PREL64",
            Self::Prel32 => "R_AARCH64_PREL32",
            Self::Call26 => "R_AARCH64_CALL26",
            Self::Jump26 => "R_AARCH64_JUMP26",
            Self::Copy => "R_AARCH64_COPY",
            Self::GlobDat => "R_AARCH64_GLOB_DAT",
            Self::JmpSlot => "R_AARCH64_JUMP_SLOT",
            Self::Relative => "R_AARCH64_RELATIVE",
            Self::TlsDesc => "R_AARCH64_TLSDESC",
            Self::TlsDescCall => "R_AARCH64_TLSDESC_CALL",
            Self::IRelative => "R_AARCH64_IRELATIVE",
            Self::AdrPrelPg21 => "R_AARCH64_ADR_PREL_PG_HI21",
            Self::AddAbsLo12Nc => "R_AARCH64_ADD_ABS_LO12_NC",
            _ => "R_AARCH64_<unknown>",
        }
    }

    /// Return `true` for IFUNC relocations.
    #[must_use]
    pub const fn is_ifunc(self) -> bool {
        matches!(self, Self::IRelative)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MIPS  (EM_MIPS)
// ─────────────────────────────────────────────────────────────────────────────

/// Relocation types for MIPS.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MipsReloc {
    None,
    Abs16,
    Abs32,
    Rel32,
    Abs26,
    HiAbs16,
    LoAbs16,
    GpRel16,
    Literal,
    Got16,
    Pc16,
    Call16,
    GpRel32,
    GlobDat,
    JmpSlot,
    Shift5,
    Shift6,
    Abs64,
    Copy,
    JumpSlot,
    Relative,
    InsertA,
    InsertB,
    Delete,
    HigherS,
    HighestS,
    Other(u32),
}

impl MipsReloc {
    /// Parse from raw `r_type`.
    #[must_use]
    pub const fn from_raw(t: u32) -> Self {
        match t {
            0 => Self::None,
            1 => Self::Abs16,
            2 => Self::Abs32,
            3 => Self::Rel32,
            4 => Self::Abs26,
            5 => Self::HiAbs16,
            6 => Self::LoAbs16,
            7 => Self::GpRel16,
            8 => Self::Literal,
            9 => Self::Got16,
            10 => Self::Pc16,
            11 => Self::Call16,
            12 => Self::GpRel32,
            51 => Self::GlobDat,
            127 => Self::Copy,
            _ => Self::Other(t),
        }
    }

    /// Return a human-readable name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::None => "R_MIPS_NONE",
            Self::Abs16 => "R_MIPS_16",
            Self::Abs32 => "R_MIPS_32",
            Self::Rel32 => "R_MIPS_REL32",
            Self::Abs26 => "R_MIPS_26",
            Self::HiAbs16 => "R_MIPS_HI16",
            Self::LoAbs16 => "R_MIPS_LO16",
            Self::GpRel16 => "R_MIPS_GPREL16",
            Self::Got16 => "R_MIPS_GOT16",
            Self::Pc16 => "R_MIPS_PC16",
            Self::Call16 => "R_MIPS_CALL16",
            Self::GpRel32 => "R_MIPS_GPREL32",
            Self::GlobDat => "R_MIPS_GLOB_DAT",
            Self::Copy => "R_MIPS_COPY",
            _ => "R_MIPS_<unknown>",
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// RISC-V  (EM_RISCV)
// ─────────────────────────────────────────────────────────────────────────────

/// Relocation types for RISC-V.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RiscVReloc {
    None,
    Abs32,
    Abs64,
    Relative,
    Copy,
    JmpSlot,
    TlsDtpmod32,
    TlsDtpmod64,
    TlsDtprel32,
    TlsDtprel64,
    TlsTprel32,
    TlsTprel64,
    Branch,
    Jal,
    Call,
    CallPlt,
    GotHi20,
    GotLo12,
    HiAbs20,
    LoAbs12,
    PcRelHi20,
    PcRelLo12I,
    PcRelLo12S,
    Hi20,
    Lo12I,
    Lo12S,
    Add8,
    Add16,
    Add32,
    Add64,
    Sub8,
    Sub16,
    Sub32,
    Sub64,
    IRelative,
    Other(u32),
}

impl RiscVReloc {
    /// Parse from raw `r_type`.
    #[must_use]
    pub const fn from_raw(t: u32) -> Self {
        match t {
            0 => Self::None,
            1 => Self::Abs32,
            2 => Self::Abs64,
            3 => Self::Relative,
            4 => Self::Copy,
            5 => Self::JmpSlot,
            6 => Self::TlsDtpmod32,
            7 => Self::TlsDtpmod64,
            8 => Self::TlsDtprel32,
            9 => Self::TlsDtprel64,
            10 => Self::TlsTprel32,
            11 => Self::TlsTprel64,
            16 => Self::Branch,
            17 => Self::Jal,
            18 => Self::Call,
            19 => Self::CallPlt,
            20 => Self::GotHi20,
            23 => Self::PcRelHi20,
            24 => Self::PcRelLo12I,
            25 => Self::PcRelLo12S,
            26 => Self::Hi20,
            27 => Self::Lo12I,
            28 => Self::Lo12S,
            33 => Self::Add8,
            34 => Self::Add16,
            35 => Self::Add32,
            36 => Self::Add64,
            37 => Self::Sub8,
            38 => Self::Sub16,
            39 => Self::Sub32,
            40 => Self::Sub64,
            58 => Self::IRelative,
            _ => Self::Other(t),
        }
    }

    /// Return a human-readable name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::None => "R_RISCV_NONE",
            Self::Abs32 => "R_RISCV_32",
            Self::Abs64 => "R_RISCV_64",
            Self::Relative => "R_RISCV_RELATIVE",
            Self::Copy => "R_RISCV_COPY",
            Self::JmpSlot => "R_RISCV_JUMP_SLOT",
            Self::Branch => "R_RISCV_BRANCH",
            Self::Jal => "R_RISCV_JAL",
            Self::Call => "R_RISCV_CALL",
            Self::CallPlt => "R_RISCV_CALL_PLT",
            Self::GotHi20 => "R_RISCV_GOT_HI20",
            Self::PcRelHi20 => "R_RISCV_PCREL_HI20",
            Self::PcRelLo12I => "R_RISCV_PCREL_LO12_I",
            Self::Hi20 => "R_RISCV_HI20",
            Self::Lo12I => "R_RISCV_LO12_I",
            Self::Add32 => "R_RISCV_ADD32",
            Self::Sub32 => "R_RISCV_SUB32",
            Self::IRelative => "R_RISCV_IRELATIVE",
            _ => "R_RISCV_<unknown>",
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PowerPC  (EM_PPC 32-bit)
// ─────────────────────────────────────────────────────────────────────────────

/// Relocation types for 32-bit PowerPC.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PpcReloc {
    None,
    Addr32,
    Addr24,
    Addr16,
    Addr16Lo,
    Addr16Hi,
    Addr16Ha,
    Addr14,
    Rel24,
    Rel14,
    Got16,
    Copy,
    GlobDat,
    JmpSlot,
    Relative,
    Local24Pc,
    Uaddr32,
    Uaddr16,
    Rel32,
    Plt32,
    PltRel32,
    PltLo,
    PltHi,
    PltHa,
    Sdarel16,
    Sectoff,
    SectoffLo,
    SectoffHi,
    SectoffHa,
    Addr30,
    IRelative,
    Other(u32),
}

impl PpcReloc {
    /// Parse from raw `r_type`.
    #[must_use]
    pub const fn from_raw(t: u32) -> Self {
        match t {
            0 => Self::None,
            1 => Self::Addr32,
            2 => Self::Addr24,
            3 => Self::Addr16,
            4 => Self::Addr16Lo,
            5 => Self::Addr16Hi,
            6 => Self::Addr16Ha,
            7 => Self::Addr14,
            10 => Self::Rel24,
            11 => Self::Rel14,
            15 => Self::Got16,
            19 => Self::Copy,
            20 => Self::GlobDat,
            21 => Self::JmpSlot,
            22 => Self::Relative,
            248 => Self::IRelative,
            _ => Self::Other(t),
        }
    }

    /// Return a human-readable name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::None => "R_PPC_NONE",
            Self::Addr32 => "R_PPC_ADDR32",
            Self::Addr24 => "R_PPC_ADDR24",
            Self::Addr16 => "R_PPC_ADDR16",
            Self::Addr16Lo => "R_PPC_ADDR16_LO",
            Self::Addr16Hi => "R_PPC_ADDR16_HI",
            Self::Addr16Ha => "R_PPC_ADDR16_HA",
            Self::Rel24 => "R_PPC_REL24",
            Self::Got16 => "R_PPC_GOT16",
            Self::Copy => "R_PPC_COPY",
            Self::GlobDat => "R_PPC_GLOB_DAT",
            Self::JmpSlot => "R_PPC_JMP_SLOT",
            Self::Relative => "R_PPC_RELATIVE",
            Self::IRelative => "R_PPC_IRELATIVE",
            _ => "R_PPC_<unknown>",
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PowerPC64  (EM_PPC64)
// ─────────────────────────────────────────────────────────────────────────────

/// Relocation types for 64-bit PowerPC.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Ppc64Reloc {
    None,
    Addr32,
    Addr64,
    Addr16,
    Addr16Lo,
    Addr16Hi,
    Addr16Ha,
    Addr14,
    Rel24,
    Rel32,
    Rel64,
    Got16,
    GotLo,
    GotHi,
    GotHa,
    Copy,
    GlobDat,
    JmpSlot,
    Relative,
    Uaddr32,
    Uaddr64,
    TocRel16,
    Toc16Lo,
    Toc16Hi,
    Toc16Ha,
    TocRel64,
    IRelative,
    Other(u32),
}

impl Ppc64Reloc {
    /// Parse from raw `r_type`.
    #[must_use]
    pub const fn from_raw(t: u32) -> Self {
        match t {
            0 => Self::None,
            1 => Self::Addr32,
            38 => Self::Addr64,
            3 => Self::Addr16,
            4 => Self::Addr16Lo,
            5 => Self::Addr16Hi,
            6 => Self::Addr16Ha,
            7 => Self::Addr14,
            10 => Self::Rel24,
            26 => Self::Rel32,
            44 => Self::Rel64,
            15 => Self::Got16,
            52 => Self::Copy,
            53 => Self::GlobDat,
            21 => Self::JmpSlot,
            22 => Self::Relative,
            248 => Self::IRelative,
            _ => Self::Other(t),
        }
    }

    /// Return a human-readable name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::None => "R_PPC64_NONE",
            Self::Addr32 => "R_PPC64_ADDR32",
            Self::Addr64 => "R_PPC64_ADDR64",
            Self::Addr16Lo => "R_PPC64_ADDR16_LO",
            Self::Addr16Hi => "R_PPC64_ADDR16_HI",
            Self::Addr16Ha => "R_PPC64_ADDR16_HA",
            Self::Rel24 => "R_PPC64_REL24",
            Self::Copy => "R_PPC64_COPY",
            Self::GlobDat => "R_PPC64_GLOB_DAT",
            Self::JmpSlot => "R_PPC64_JMP_SLOT",
            Self::Relative => "R_PPC64_RELATIVE",
            Self::IRelative => "R_PPC64_IRELATIVE",
            _ => "R_PPC64_<unknown>",
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SPARC  (EM_SPARC / EM_SPARCV9)
// ─────────────────────────────────────────────────────────────────────────────

/// Relocation types for SPARC (32-bit and 64-bit).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SparcReloc {
    None,
    Abs8,
    Abs16,
    Abs32,
    Disp8,
    Disp16,
    Disp32,
    Wdisp30,
    Wdisp22,
    HiAbs22,
    LoAbs10,
    LoAbs8,
    Copy,
    GlobDat,
    JmpSlot,
    Relative,
    Ua32,
    Plt32,
    Hiplt22,
    Loplt10,
    PcPlt32,
    PcPlt22,
    PcPlt10,
    Hi22,
    Lo10,
    GotHi22,
    GotLo10,
    GotLo22,
    GotHix22,
    GotLox10,
    GlobJmp,
    SparcJmpSlot,
    Abs64,
    Prel64,
    IRelative,
    Other(u32),
}

impl SparcReloc {
    /// Parse from raw `r_type`.
    #[must_use]
    pub const fn from_raw(t: u32) -> Self {
        match t {
            0 => Self::None,
            1 => Self::Abs8,
            2 => Self::Abs16,
            3 => Self::Abs32,
            4 => Self::Disp8,
            5 => Self::Disp16,
            6 => Self::Disp32,
            7 => Self::Wdisp30,
            8 => Self::Wdisp22,
            9 => Self::HiAbs22,
            10 => Self::LoAbs10,
            19 => Self::Copy,
            20 => Self::GlobDat,
            21 => Self::JmpSlot,
            22 => Self::Relative,
            23 => Self::Ua32,
            _ => Self::Other(t),
        }
    }

    /// Return a human-readable name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::None => "R_SPARC_NONE",
            Self::Abs8 => "R_SPARC_8",
            Self::Abs16 => "R_SPARC_16",
            Self::Abs32 => "R_SPARC_32",
            Self::Disp8 => "R_SPARC_DISP8",
            Self::Disp16 => "R_SPARC_DISP16",
            Self::Disp32 => "R_SPARC_DISP32",
            Self::Wdisp30 => "R_SPARC_WDISP30",
            Self::HiAbs22 => "R_SPARC_HI22",
            Self::LoAbs10 => "R_SPARC_LO10",
            Self::Copy => "R_SPARC_COPY",
            Self::GlobDat => "R_SPARC_GLOB_DAT",
            Self::JmpSlot => "R_SPARC_JMP_SLOT",
            Self::Relative => "R_SPARC_RELATIVE",
            Self::Ua32 => "R_SPARC_UA32",
            Self::Abs64 => "R_SPARC_64",
            Self::Prel64 => "R_SPARC_DISP64",
            _ => "R_SPARC_<unknown>",
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Generic parsed relocation entry
// ─────────────────────────────────────────────────────────────────────────────

/// A parsed ELF `Rel` entry (without addend).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelEntry {
    /// Address at which the relocation should be applied.
    pub offset: u64,
    /// Raw symbol table index.
    pub sym_idx: u32,
    /// Raw relocation type.
    pub rel_type: u32,
}

impl RelEntry {
    /// Parse a 64-bit little-endian `Elf64_Rel` from a 16-byte slice.
    ///
    /// # Errors
    ///
    /// Returns `Err(String)` if `data` is shorter than 16 bytes.
    ///
    /// # Panics
    ///
    /// Panics if internal slice-to-array conversion fails (unreachable after the length check).
    pub fn parse64_le(data: &[u8]) -> Result<Self, String> {
        if data.len() < 16 {
            return Err(format!("Elf64_Rel too short: {} bytes", data.len()));
        }
        let offset = u64::from_le_bytes(data[0..8].try_into().unwrap());
        let info = u64::from_le_bytes(data[8..16].try_into().unwrap());
        let sym_idx = (info >> 32) as u32;
        let rel_type = (info & 0xffff_ffff) as u32;
        Ok(Self {
            offset,
            sym_idx,
            rel_type,
        })
    }

    /// Parse a 32-bit little-endian `Elf32_Rel` from an 8-byte slice.
    ///
    /// # Errors
    ///
    /// Returns `Err(String)` if `data` is shorter than 8 bytes.
    ///
    /// # Panics
    ///
    /// Panics if internal slice-to-array conversion fails (unreachable after the length check).
    pub fn parse32_le(data: &[u8]) -> Result<Self, String> {
        if data.len() < 8 {
            return Err(format!("Elf32_Rel too short: {} bytes", data.len()));
        }
        let offset = u64::from(u32::from_le_bytes(data[0..4].try_into().unwrap()));
        let info = u32::from_le_bytes(data[4..8].try_into().unwrap());
        let sym_idx = info >> 8;
        let rel_type = info & 0xff;
        Ok(Self {
            offset,
            sym_idx,
            rel_type,
        })
    }
}

/// A parsed ELF `Rela` entry (with explicit addend).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelaEntry {
    /// Address at which the relocation should be applied.
    pub offset: u64,
    /// Raw symbol table index.
    pub sym_idx: u32,
    /// Raw relocation type.
    pub rel_type: u32,
    /// Explicit addend.
    pub addend: i64,
}

impl RelaEntry {
    /// Parse a 64-bit little-endian `Elf64_Rela` from a 24-byte slice.
    ///
    /// # Errors
    ///
    /// Returns `Err(String)` if `data` is shorter than 24 bytes.
    ///
    /// # Panics
    ///
    /// Panics if internal slice-to-array conversion fails (unreachable after the length check).
    pub fn parse64_le(data: &[u8]) -> Result<Self, String> {
        if data.len() < 24 {
            return Err(format!("Elf64_Rela too short: {} bytes", data.len()));
        }
        let offset = u64::from_le_bytes(data[0..8].try_into().unwrap());
        let info = u64::from_le_bytes(data[8..16].try_into().unwrap());
        let addend = i64::from_le_bytes(data[16..24].try_into().unwrap());
        let sym_idx = (info >> 32) as u32;
        let rel_type = (info & 0xffff_ffff) as u32;
        Ok(Self {
            offset,
            sym_idx,
            rel_type,
            addend,
        })
    }

    /// Parse a 32-bit little-endian `Elf32_Rela` from a 12-byte slice.
    ///
    /// # Errors
    ///
    /// Returns `Err(String)` if `data` is shorter than 12 bytes.
    ///
    /// # Panics
    ///
    /// Panics if internal slice-to-array conversion fails (unreachable after the length check).
    pub fn parse32_le(data: &[u8]) -> Result<Self, String> {
        if data.len() < 12 {
            return Err(format!("Elf32_Rela too short: {} bytes", data.len()));
        }
        let offset = u64::from(u32::from_le_bytes(data[0..4].try_into().unwrap()));
        let info = u32::from_le_bytes(data[4..8].try_into().unwrap());
        let addend = i64::from(i32::from_le_bytes(data[8..12].try_into().unwrap()));
        let sym_idx = info >> 8;
        let rel_type = info & 0xff;
        Ok(Self {
            offset,
            sym_idx,
            rel_type,
            addend,
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// RelocTable  — a collection of relocation entries
// ─────────────────────────────────────────────────────────────────────────────

/// A parsed ELF relocation table, either `SHT_REL` or `SHT_RELA`.
#[derive(Debug, Clone)]
pub struct RelocTable {
    /// Section name (e.g. `".rela.plt"`, `".rel.dyn"`).
    pub section_name: String,
    /// Whether entries have an explicit addend (`true`) or not (`false`).
    pub is_rela: bool,
    /// Parsed `Rela` entries (populated when `is_rela == true`).
    pub rela_entries: Vec<RelaEntry>,
    /// Parsed `Rel` entries (populated when `is_rela == false`).
    pub rel_entries: Vec<RelEntry>,
}

impl RelocTable {
    /// Parse a 64-bit little-endian `SHT_RELA` section.
    ///
    /// # Errors
    ///
    /// Returns `Err(String)` if any entry cannot be parsed.
    pub fn parse_rela64_le(name: impl Into<String>, data: &[u8]) -> Result<Self, String> {
        let name = name.into();
        let count = data.len() / 24;
        let mut rela_entries = Vec::with_capacity(count);
        for i in 0..count {
            let entry = RelaEntry::parse64_le(&data[i * 24..])?;
            rela_entries.push(entry);
        }
        Ok(Self {
            section_name: name,
            is_rela: true,
            rela_entries,
            rel_entries: Vec::new(),
        })
    }

    /// Parse a 64-bit little-endian `SHT_REL` section.
    ///
    /// # Errors
    ///
    /// Returns `Err(String)` if any entry cannot be parsed.
    pub fn parse_rel64_le(name: impl Into<String>, data: &[u8]) -> Result<Self, String> {
        let name = name.into();
        let count = data.len() / 16;
        let mut rel_entries = Vec::with_capacity(count);
        for i in 0..count {
            let entry = RelEntry::parse64_le(&data[i * 16..])?;
            rel_entries.push(entry);
        }
        Ok(Self {
            section_name: name,
            is_rela: false,
            rela_entries: Vec::new(),
            rel_entries,
        })
    }

    /// Total number of relocation entries.
    #[must_use]
    pub const fn len(&self) -> usize {
        if self.is_rela {
            self.rela_entries.len()
        } else {
            self.rel_entries.len()
        }
    }

    /// Return `true` if the table has no entries.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Return all relocation types present in this table (deduplicated).
    #[must_use]
    pub fn unique_types(&self) -> Vec<u32> {
        let mut types: Vec<u32> = if self.is_rela {
            self.rela_entries.iter().map(|e| e.rel_type).collect()
        } else {
            self.rel_entries.iter().map(|e| e.rel_type).collect()
        };
        types.sort_unstable();
        types.dedup();
        types
    }

    /// Return all entries that target a given symbol index.
    #[must_use]
    pub fn entries_for_sym(&self, sym_idx: u32) -> Vec<u64> {
        if self.is_rela {
            self.rela_entries
                .iter()
                .filter(|e| e.sym_idx == sym_idx)
                .map(|e| e.offset)
                .collect()
        } else {
            self.rel_entries
                .iter()
                .filter(|e| e.sym_idx == sym_idx)
                .map(|e| e.offset)
                .collect()
        }
    }

    /// Return all offsets in the table.
    #[must_use]
    pub fn offsets(&self) -> Vec<u64> {
        if self.is_rela {
            self.rela_entries.iter().map(|e| e.offset).collect()
        } else {
            self.rel_entries.iter().map(|e| e.offset).collect()
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── x86 ──────────────────────────────────────────────────────────────────

    #[test]
    fn test_x86_reloc_round_trip() {
        let types = [0u32, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        for t in types {
            assert_eq!(X86Reloc::from_raw(t).as_raw(), t);
        }
    }

    #[test]
    fn test_x86_reloc_name() {
        assert_eq!(X86Reloc::from_raw(0).name(), "R_386_NONE");
        assert_eq!(X86Reloc::from_raw(7).name(), "R_386_JMP_SLOT");
        assert_eq!(X86Reloc::from_raw(5).name(), "R_386_COPY");
    }

    #[test]
    fn test_x86_reloc_is_plt() {
        assert!(X86Reloc::Plt32.is_plt());
        assert!(X86Reloc::JmpSlot.is_plt());
        assert!(!X86Reloc::Abs32.is_plt());
    }

    #[test]
    fn test_x86_reloc_unknown() {
        let r = X86Reloc::from_raw(999);
        assert!(matches!(r, X86Reloc::Other(999)));
        assert_eq!(r.name(), "R_386_<unknown>");
    }

    // ── x86-64 ───────────────────────────────────────────────────────────────

    #[test]
    fn test_x86_64_reloc_round_trip() {
        let types = [0u32, 1, 2, 4, 7, 8, 37];
        for t in types {
            assert_eq!(X86_64Reloc::from_raw(t).as_raw(), t);
        }
    }

    #[test]
    fn test_x86_64_reloc_name() {
        assert_eq!(X86_64Reloc::from_raw(0).name(), "R_X86_64_NONE");
        assert_eq!(X86_64Reloc::from_raw(7).name(), "R_X86_64_JUMP_SLOT");
        assert_eq!(X86_64Reloc::from_raw(37).name(), "R_X86_64_IRELATIVE");
    }

    #[test]
    fn test_x86_64_reloc_is_jmp_slot() {
        assert!(X86_64Reloc::JmpSlot.is_jmp_slot());
        assert!(!X86_64Reloc::Abs64.is_jmp_slot());
    }

    #[test]
    fn test_x86_64_reloc_is_ifunc() {
        assert!(X86_64Reloc::IRelative.is_ifunc());
        assert!(!X86_64Reloc::JmpSlot.is_ifunc());
    }

    // ── ARM ──────────────────────────────────────────────────────────────────

    #[test]
    fn test_arm_reloc_from_raw() {
        assert_eq!(ArmReloc::from_raw(0), ArmReloc::None);
        assert_eq!(ArmReloc::from_raw(22), ArmReloc::JmpSlot);
    }

    #[test]
    fn test_arm_reloc_is_thumb() {
        assert!(ArmReloc::ThmbCall.is_thumb());
        assert!(!ArmReloc::Jump24.is_thumb());
    }

    // ── AArch64 ──────────────────────────────────────────────────────────────

    #[test]
    fn test_aarch64_reloc_from_raw() {
        assert_eq!(Aarch64Reloc::from_raw(0), Aarch64Reloc::None);
        assert_eq!(Aarch64Reloc::from_raw(1026), Aarch64Reloc::JmpSlot);
    }

    #[test]
    fn test_aarch64_reloc_is_ifunc() {
        assert!(Aarch64Reloc::IRelative.is_ifunc());
        assert!(!Aarch64Reloc::GlobDat.is_ifunc());
    }

    // ── MIPS ─────────────────────────────────────────────────────────────────

    #[test]
    fn test_mips_reloc_from_raw() {
        assert_eq!(MipsReloc::from_raw(0), MipsReloc::None);
        assert_eq!(MipsReloc::from_raw(9), MipsReloc::Got16);
    }

    #[test]
    fn test_mips_reloc_name() {
        assert_eq!(MipsReloc::from_raw(0).name(), "R_MIPS_NONE");
        assert_eq!(MipsReloc::from_raw(9).name(), "R_MIPS_GOT16");
    }

    // ── RISC-V ───────────────────────────────────────────────────────────────

    #[test]
    fn test_riscv_reloc_from_raw() {
        assert_eq!(RiscVReloc::from_raw(0), RiscVReloc::None);
        assert_eq!(RiscVReloc::from_raw(5), RiscVReloc::JmpSlot);
        assert_eq!(RiscVReloc::from_raw(58), RiscVReloc::IRelative);
    }

    #[test]
    fn test_riscv_reloc_name() {
        assert_eq!(RiscVReloc::from_raw(18).name(), "R_RISCV_CALL");
    }

    // ── PPC ──────────────────────────────────────────────────────────────────

    #[test]
    fn test_ppc_reloc_from_raw() {
        assert_eq!(PpcReloc::from_raw(0), PpcReloc::None);
        assert_eq!(PpcReloc::from_raw(21), PpcReloc::JmpSlot);
    }

    #[test]
    fn test_ppc64_reloc_from_raw() {
        assert_eq!(Ppc64Reloc::from_raw(0), Ppc64Reloc::None);
        assert_eq!(Ppc64Reloc::from_raw(38), Ppc64Reloc::Addr64);
    }

    // ── SPARC ────────────────────────────────────────────────────────────────

    #[test]
    fn test_sparc_reloc_from_raw() {
        assert_eq!(SparcReloc::from_raw(0), SparcReloc::None);
        assert_eq!(SparcReloc::from_raw(21), SparcReloc::JmpSlot);
    }

    // ── RelEntry / RelaEntry ─────────────────────────────────────────────────

    #[test]
    fn test_rel_entry_parse64_le() {
        // offset=0x1000, info = (sym=2 << 32) | type=7
        let offset: u64 = 0x1000;
        let info: u64 = (2u64 << 32) | 7;
        let mut data = vec![0u8; 16];
        data[0..8].copy_from_slice(&offset.to_le_bytes());
        data[8..16].copy_from_slice(&info.to_le_bytes());
        let e = RelEntry::parse64_le(&data).unwrap();
        assert_eq!(e.offset, 0x1000);
        assert_eq!(e.sym_idx, 2);
        assert_eq!(e.rel_type, 7);
    }

    #[test]
    fn test_rel_entry_parse64_le_too_short() {
        assert!(RelEntry::parse64_le(&[0u8; 8]).is_err());
    }

    #[test]
    fn test_rela_entry_parse64_le() {
        let offset: u64 = 0x2000;
        let info: u64 = (5u64 << 32) | 6;
        let addend: i64 = -4;
        let mut data = vec![0u8; 24];
        data[0..8].copy_from_slice(&offset.to_le_bytes());
        data[8..16].copy_from_slice(&info.to_le_bytes());
        data[16..24].copy_from_slice(&addend.to_le_bytes());
        let e = RelaEntry::parse64_le(&data).unwrap();
        assert_eq!(e.offset, 0x2000);
        assert_eq!(e.sym_idx, 5);
        assert_eq!(e.rel_type, 6);
        assert_eq!(e.addend, -4);
    }

    #[test]
    fn test_rela_entry_parse64_le_too_short() {
        assert!(RelaEntry::parse64_le(&[0u8; 8]).is_err());
    }

    // ── RelocTable ───────────────────────────────────────────────────────────

    #[test]
    fn test_reloc_table_rela64_parse() {
        // 2 entries
        let offset1: u64 = 0x1000;
        let info1: u64 = (1u64 << 32) | 7;
        let addend1: i64 = 0;
        let offset2: u64 = 0x2000;
        let info2: u64 = (2u64 << 32) | 7;
        let addend2: i64 = 4;
        let mut data = vec![0u8; 48];
        data[0..8].copy_from_slice(&offset1.to_le_bytes());
        data[8..16].copy_from_slice(&info1.to_le_bytes());
        data[16..24].copy_from_slice(&addend1.to_le_bytes());
        data[24..32].copy_from_slice(&offset2.to_le_bytes());
        data[32..40].copy_from_slice(&info2.to_le_bytes());
        data[40..48].copy_from_slice(&addend2.to_le_bytes());
        let tbl = RelocTable::parse_rela64_le(".rela.plt", &data).unwrap();
        assert_eq!(tbl.len(), 2);
        assert!(!tbl.is_empty());
        assert!(tbl.is_rela);
        assert_eq!(tbl.section_name, ".rela.plt");
    }

    #[test]
    fn test_reloc_table_empty() {
        let tbl = RelocTable::parse_rela64_le(".rela.dyn", &[]).unwrap();
        assert!(tbl.is_empty());
        assert_eq!(tbl.len(), 0);
    }

    #[test]
    fn test_reloc_table_unique_types() {
        // 2 entries, both type 7
        let offset: u64 = 0x1000;
        let info: u64 = (1u64 << 32) | 7;
        let addend: i64 = 0;
        let mut data = vec![0u8; 48];
        data[0..8].copy_from_slice(&offset.to_le_bytes());
        data[8..16].copy_from_slice(&info.to_le_bytes());
        data[16..24].copy_from_slice(&addend.to_le_bytes());
        let offset2: u64 = 0x2000;
        let info2: u64 = (2u64 << 32) | 7;
        data[24..32].copy_from_slice(&offset2.to_le_bytes());
        data[32..40].copy_from_slice(&info2.to_le_bytes());
        // addend2 already zeros
        let tbl = RelocTable::parse_rela64_le(".rela.plt", &data).unwrap();
        assert_eq!(tbl.unique_types(), vec![7u32]);
    }

    #[test]
    fn test_reloc_table_offsets() {
        let mut data = vec![0u8; 24];
        let offset: u64 = 0xdead_beef;
        data[0..8].copy_from_slice(&offset.to_le_bytes());
        let info: u64 = 7;
        data[8..16].copy_from_slice(&info.to_le_bytes());
        let tbl = RelocTable::parse_rela64_le(".rela.text", &data).unwrap();
        assert_eq!(tbl.offsets(), vec![0xdead_beef_u64]);
    }

    #[test]
    fn test_reloc_table_entries_for_sym() {
        let mut data = vec![0u8; 24];
        let offset: u64 = 0x5000;
        let info: u64 = (42u64 << 32) | 6;
        data[0..8].copy_from_slice(&offset.to_le_bytes());
        data[8..16].copy_from_slice(&info.to_le_bytes());
        let tbl = RelocTable::parse_rela64_le(".rela.dyn", &data).unwrap();
        assert_eq!(tbl.entries_for_sym(42), vec![0x5000u64]);
        assert!(tbl.entries_for_sym(0).is_empty());
    }
}
