//! SSE/SSE2/SSE3/SSSE3/SSE4.1/SSE4.2 instruction definitions.
//!
//! Each variant carries its encoding group and a human-readable description.
//! The tables here are used by the disassembler to annotate decoded instructions
//! with richer semantic information beyond the raw mnemonic.
//!
//! # Layer distinction
//!
//! This module provides **static descriptor tables** for SSE instructions:
//! [`SseInstr`] entries are `const`-constructed and indexed by opcode byte.
//! They are used for *annotation* (adding category / description metadata to
//! an already-decoded instruction) and depend on [`crate::tables::OpEnc`] for
//! their operand-encoding field.
//!
//! For **runtime SIMD decoding** â€” which drives `iced-x86` to fully decode
//! and classify SSE/AVX/AVX-512 instructions including vector widths, AVX-512
//! masking, and subgroup detection â€” see [`crate::x86_simd_decoder`].
//! The two modules cover the same SIMD family from different angles and are
//! intentionally kept separate.
//!
//! # Dispatch status (NOT wired into `src/lift.rs`)
//!
//! This module is **not** part of the active lifting path. `src/lift.rs`
//! dispatches every mnemonic directly via its own native match arms (added
//! across several hardening passes), and does not call into this module.
//! It is intentionally retained -- not dead code pending removal -- per
//! explicit user instruction, as a possible future cross-validation /
//! second-opinion decode path independent of `lift.rs`.

use crate::tables::OpEnc;

// ---------------------------------------------------------------------------
// SSE prefix flags
// ---------------------------------------------------------------------------

/// Mandatory-prefix flags for an SSE instruction.
#[derive(Debug, Clone, Copy)]
pub struct SsePfx {
    /// Whether the instruction requires the 66h operand-size prefix.
    pub p66: bool,
    /// Whether the instruction requires the F2h REPNE prefix.
    pub pf2: bool,
    /// Whether the instruction requires the F3h REP prefix.
    pub pf3: bool,
}

impl SsePfx {
    const fn none() -> Self { Self { p66: false, pf2: false, pf3: false } }
    const fn p66() -> Self { Self { p66: true, pf2: false, pf3: false } }
    const fn pf2() -> Self { Self { p66: false, pf2: true, pf3: false } }
    const fn pf3() -> Self { Self { p66: false, pf2: false, pf3: true } }
}

// ---------------------------------------------------------------------------
// SSE instruction category
// ---------------------------------------------------------------------------

/// High-level category of an SSE instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[must_use]
pub enum SseCategory {
    /// Data movement (MOVAPS, MOVUPS, MOVSS, MOVSD, MOVDQA, â€¦).
    Move,
    /// Arithmetic (ADDPS, SUBPS, MULPS, DIVPS, SQRTPS, â€¦).
    Arithmetic,
    /// Comparison (CMPPS, UCOMISS, UCOMISD, PCMPEQB, â€¦).
    Compare,
    /// Logical (ANDPS, ORPS, XORPS, ANDNPS, PAND, POR, PXOR, â€¦).
    Logical,
    /// Shuffle / permutation (SHUFPS, PSHUFD, PSHUFB, â€¦).
    Shuffle,
    /// Pack / unpack (PACKSS, PACKUS, PUNPCKLBW, â€¦).
    Pack,
    /// Conversion (CVTPS2PD, CVTDQ2PS, CVTTSS2SI, â€¦).
    Convert,
    /// Cache / memory hints (PREFETCHT0, PREFETCHNTA, SFENCE, MFENCE, â€¦).
    Cache,
    /// Bit manipulation specific to SSE (PSLLD, PSRLD, PSRAD, â€¦).
    Shift,
    /// Dot product / horizontal arithmetic (DPPS, HADDPS, PHADDW, â€¦).
    HorizontalArith,
    /// String / text processing (PCMPISTRI, PCMPESTRI, â€¦) â€” SSE4.2.
    StringText,
    /// CRC32 â€” SSE4.2.
    Crc,
    /// Blend / insert / extract â€” SSE4.1.
    BlendInsertExtract,
    /// AES / PCLMULQDQ â€” separate extension but often grouped with SSE.
    Crypto,
}

// ---------------------------------------------------------------------------
// SSE instruction descriptor
// ---------------------------------------------------------------------------

/// Descriptor for one SSE-family instruction.
#[derive(Debug, Clone, Copy)]
#[must_use]
pub struct SseInstr {
    /// Mnemonic string (base; no prefix disambiguation).
    pub mnemonic: &'static str,
    /// The opcode byte (second byte of 0F xx, or 0F38/0F3A secondary byte).
    pub opcode: u8,
    /// Mandatory-prefix requirement flags.
    pub pfx: SsePfx,
    /// The operand encoding.
    pub enc: OpEnc,
    /// Semantic category.
    pub category: SseCategory,
    /// One-line description.
    pub description: &'static str,
}

impl SseInstr {
    const fn new(
        mnemonic: &'static str,
        opcode: u8,
        pfx: SsePfx,
        enc: OpEnc,
        category: SseCategory,
        description: &'static str,
    ) -> Self {
        Self { mnemonic, opcode, pfx, enc, category, description }
    }
}

// ---------------------------------------------------------------------------
// SSE (plain, no mandatory prefix) â€” 0F xx
// ---------------------------------------------------------------------------

/// SSE instructions without a mandatory prefix (0F xx, no 66/F2/F3).
pub static SSE_NP: &[SseInstr] = &[
    SseInstr::new(
        "movups",
        0x10,
        SsePfx::none(),
        OpEnc::RM,
        SseCategory::Move,
        "Move Unaligned Packed Single-FP",
    ),
    SseInstr::new(
        "movups",
        0x11,
        SsePfx::none(),
        OpEnc::MR,
        SseCategory::Move,
        "Move Unaligned Packed Single-FP (store)",
    ),
    SseInstr::new(
        "movlps",
        0x12,
        SsePfx::none(),
        OpEnc::RM,
        SseCategory::Move,
        "Move Low Packed Single-FP",
    ),
    SseInstr::new(
        "movlps",
        0x13,
        SsePfx::none(),
        OpEnc::MR,
        SseCategory::Move,
        "Move Low Packed Single-FP (store)",
    ),
    SseInstr::new(
        "unpcklps",
        0x14,
        SsePfx::none(),
        OpEnc::RM,
        SseCategory::Pack,
        "Unpack Low Packed Single-FP",
    ),
    SseInstr::new(
        "unpckhps",
        0x15,
        SsePfx::none(),
        OpEnc::RM,
        SseCategory::Pack,
        "Unpack High Packed Single-FP",
    ),
    SseInstr::new(
        "movhps",
        0x16,
        SsePfx::none(),
        OpEnc::RM,
        SseCategory::Move,
        "Move High Packed Single-FP (load)",
    ),
    SseInstr::new(
        "movhps",
        0x17,
        SsePfx::none(),
        OpEnc::MR,
        SseCategory::Move,
        "Move High Packed Single-FP (store)",
    ),
    SseInstr::new(
        "movaps",
        0x28,
        SsePfx::none(),
        OpEnc::RM,
        SseCategory::Move,
        "Move Aligned Packed Single-FP (load)",
    ),
    SseInstr::new(
        "movaps",
        0x29,
        SsePfx::none(),
        OpEnc::MR,
        SseCategory::Move,
        "Move Aligned Packed Single-FP (store)",
    ),
    SseInstr::new(
        "cvtpi2ps",
        0x2A,
        SsePfx::none(),
        OpEnc::RM,
        SseCategory::Convert,
        "Convert Packed DW Int to Packed Single-FP",
    ),
    SseInstr::new(
        "movntps",
        0x2B,
        SsePfx::none(),
        OpEnc::MR,
        SseCategory::Cache,
        "Store Packed Single-FP Non-Temporal",
    ),
    SseInstr::new(
        "cvttps2pi",
        0x2C,
        SsePfx::none(),
        OpEnc::RM,
        SseCategory::Convert,
        "Convert with Truncation Packed Single-FP to Packed DW Int",
    ),
    SseInstr::new(
        "cvtps2pi",
        0x2D,
        SsePfx::none(),
        OpEnc::RM,
        SseCategory::Convert,
        "Convert Packed Single-FP to Packed DW Int",
    ),
    SseInstr::new(
        "ucomiss",
        0x2E,
        SsePfx::none(),
        OpEnc::RM,
        SseCategory::Compare,
        "Unordered Compare Scalar Single-FP, Set EFLAGS",
    ),
    SseInstr::new(
        "comiss",
        0x2F,
        SsePfx::none(),
        OpEnc::RM,
        SseCategory::Compare,
        "Compare Scalar Single-FP, Set EFLAGS",
    ),
    SseInstr::new(
        "movmskps",
        0x50,
        SsePfx::none(),
        OpEnc::RM,
        SseCategory::Move,
        "Extract Packed Single-FP Sign Mask",
    ),
    SseInstr::new(
        "sqrtps",
        0x51,
        SsePfx::none(),
        OpEnc::RM,
        SseCategory::Arithmetic,
        "Square Root Packed Single-FP",
    ),
    SseInstr::new(
        "rsqrtps",
        0x52,
        SsePfx::none(),
        OpEnc::RM,
        SseCategory::Arithmetic,
        "Reciprocal Square Root Packed Single-FP",
    ),
    SseInstr::new(
        "rcpps",
        0x53,
        SsePfx::none(),
        OpEnc::RM,
        SseCategory::Arithmetic,
        "Reciprocal Packed Single-FP",
    ),
    SseInstr::new(
        "andps",
        0x54,
        SsePfx::none(),
        OpEnc::RM,
        SseCategory::Logical,
        "Bitwise AND Packed Single-FP",
    ),
    SseInstr::new(
        "andnps",
        0x55,
        SsePfx::none(),
        OpEnc::RM,
        SseCategory::Logical,
        "Bitwise AND NOT Packed Single-FP",
    ),
    SseInstr::new(
        "orps",
        0x56,
        SsePfx::none(),
        OpEnc::RM,
        SseCategory::Logical,
        "Bitwise OR Packed Single-FP",
    ),
    SseInstr::new(
        "xorps",
        0x57,
        SsePfx::none(),
        OpEnc::RM,
        SseCategory::Logical,
        "Bitwise XOR Packed Single-FP",
    ),
    SseInstr::new(
        "addps",
        0x58,
        SsePfx::none(),
        OpEnc::RM,
        SseCategory::Arithmetic,
        "Add Packed Single-FP",
    ),
    SseInstr::new(
        "mulps",
        0x59,
        SsePfx::none(),
        OpEnc::RM,
        SseCategory::Arithmetic,
        "Multiply Packed Single-FP",
    ),
    SseInstr::new(
        "cvtps2pd",
        0x5A,
        SsePfx::none(),
        OpEnc::RM,
        SseCategory::Convert,
        "Convert Packed Single-FP to Double-FP",
    ),
    SseInstr::new(
        "cvtdq2ps",
        0x5B,
        SsePfx::none(),
        OpEnc::RM,
        SseCategory::Convert,
        "Convert Packed DW Int to Packed Single-FP",
    ),
    SseInstr::new(
        "subps",
        0x5C,
        SsePfx::none(),
        OpEnc::RM,
        SseCategory::Arithmetic,
        "Subtract Packed Single-FP",
    ),
    SseInstr::new(
        "minps",
        0x5D,
        SsePfx::none(),
        OpEnc::RM,
        SseCategory::Arithmetic,
        "Return Minimum Packed Single-FP",
    ),
    SseInstr::new(
        "divps",
        0x5E,
        SsePfx::none(),
        OpEnc::RM,
        SseCategory::Arithmetic,
        "Divide Packed Single-FP",
    ),
    SseInstr::new(
        "maxps",
        0x5F,
        SsePfx::none(),
        OpEnc::RM,
        SseCategory::Arithmetic,
        "Return Maximum Packed Single-FP",
    ),
    SseInstr::new(
        "cmpps",
        0xC2,
        SsePfx::none(),
        OpEnc::RMV,
        SseCategory::Compare,
        "Compare Packed Single-FP",
    ),
    SseInstr::new(
        "shufps",
        0xC6,
        SsePfx::none(),
        OpEnc::RMV,
        SseCategory::Shuffle,
        "Shuffle Packed Single-FP",
    ),
];

// ---------------------------------------------------------------------------
// SSE2 â€” mandatory 66h prefix, 0F xx
// ---------------------------------------------------------------------------

/// SSE2 instructions with mandatory 66h prefix.
pub static SSE2_66: &[SseInstr] = &[
    SseInstr::new(
        "movupd",
        0x10,
        SsePfx::p66(),
        OpEnc::RM,
        SseCategory::Move,
        "Move Unaligned Packed Double-FP",
    ),
    SseInstr::new(
        "movupd",
        0x11,
        SsePfx::p66(),
        OpEnc::MR,
        SseCategory::Move,
        "Move Unaligned Packed Double-FP (store)",
    ),
    SseInstr::new(
        "movlpd",
        0x12,
        SsePfx::p66(),
        OpEnc::RM,
        SseCategory::Move,
        "Move Low Packed Double-FP (load)",
    ),
    SseInstr::new(
        "movlpd",
        0x13,
        SsePfx::p66(),
        OpEnc::MR,
        SseCategory::Move,
        "Move Low Packed Double-FP (store)",
    ),
    SseInstr::new(
        "unpcklpd",
        0x14,
        SsePfx::p66(),
        OpEnc::RM,
        SseCategory::Pack,
        "Unpack Low Packed Double-FP",
    ),
    SseInstr::new(
        "unpckhpd",
        0x15,
        SsePfx::p66(),
        OpEnc::RM,
        SseCategory::Pack,
        "Unpack High Packed Double-FP",
    ),
    SseInstr::new(
        "movhpd",
        0x16,
        SsePfx::p66(),
        OpEnc::RM,
        SseCategory::Move,
        "Move High Packed Double-FP (load)",
    ),
    SseInstr::new(
        "movhpd",
        0x17,
        SsePfx::p66(),
        OpEnc::MR,
        SseCategory::Move,
        "Move High Packed Double-FP (store)",
    ),
    SseInstr::new(
        "movapd",
        0x28,
        SsePfx::p66(),
        OpEnc::RM,
        SseCategory::Move,
        "Move Aligned Packed Double-FP",
    ),
    SseInstr::new(
        "movapd",
        0x29,
        SsePfx::p66(),
        OpEnc::MR,
        SseCategory::Move,
        "Move Aligned Packed Double-FP (store)",
    ),
    SseInstr::new(
        "cvtpi2pd",
        0x2A,
        SsePfx::p66(),
        OpEnc::RM,
        SseCategory::Convert,
        "Convert Packed DW Int to Packed Double-FP",
    ),
    SseInstr::new(
        "movntpd",
        0x2B,
        SsePfx::p66(),
        OpEnc::MR,
        SseCategory::Cache,
        "Store Packed Double-FP Non-Temporal",
    ),
    SseInstr::new(
        "cvttpd2pi",
        0x2C,
        SsePfx::p66(),
        OpEnc::RM,
        SseCategory::Convert,
        "Convert with Truncation Packed Double-FP to Packed DW Int",
    ),
    SseInstr::new(
        "cvtpd2pi",
        0x2D,
        SsePfx::p66(),
        OpEnc::RM,
        SseCategory::Convert,
        "Convert Packed Double-FP to Packed DW Int",
    ),
    SseInstr::new(
        "ucomisd",
        0x2E,
        SsePfx::p66(),
        OpEnc::RM,
        SseCategory::Compare,
        "Unordered Compare Scalar Double-FP, Set EFLAGS",
    ),
    SseInstr::new(
        "comisd",
        0x2F,
        SsePfx::p66(),
        OpEnc::RM,
        SseCategory::Compare,
        "Compare Scalar Double-FP, Set EFLAGS",
    ),
    SseInstr::new(
        "movmskpd",
        0x50,
        SsePfx::p66(),
        OpEnc::RM,
        SseCategory::Move,
        "Extract Packed Double-FP Sign Mask",
    ),
    SseInstr::new(
        "sqrtpd",
        0x51,
        SsePfx::p66(),
        OpEnc::RM,
        SseCategory::Arithmetic,
        "Square Root Packed Double-FP",
    ),
    SseInstr::new(
        "andpd",
        0x54,
        SsePfx::p66(),
        OpEnc::RM,
        SseCategory::Logical,
        "Bitwise AND Packed Double-FP",
    ),
    SseInstr::new(
        "andnpd",
        0x55,
        SsePfx::p66(),
        OpEnc::RM,
        SseCategory::Logical,
        "Bitwise AND NOT Packed Double-FP",
    ),
    SseInstr::new(
        "orpd",
        0x56,
        SsePfx::p66(),
        OpEnc::RM,
        SseCategory::Logical,
        "Bitwise OR Packed Double-FP",
    ),
    SseInstr::new(
        "xorpd",
        0x57,
        SsePfx::p66(),
        OpEnc::RM,
        SseCategory::Logical,
        "Bitwise XOR Packed Double-FP",
    ),
    SseInstr::new(
        "addpd",
        0x58,
        SsePfx::p66(),
        OpEnc::RM,
        SseCategory::Arithmetic,
        "Add Packed Double-FP",
    ),
    SseInstr::new(
        "mulpd",
        0x59,
        SsePfx::p66(),
        OpEnc::RM,
        SseCategory::Arithmetic,
        "Multiply Packed Double-FP",
    ),
    SseInstr::new(
        "cvtpd2ps",
        0x5A,
        SsePfx::p66(),
        OpEnc::RM,
        SseCategory::Convert,
        "Convert Packed Double-FP to Single-FP",
    ),
    SseInstr::new(
        "cvtps2dq",
        0x5B,
        SsePfx::p66(),
        OpEnc::RM,
        SseCategory::Convert,
        "Convert Packed Single-FP to DW Int",
    ),
    SseInstr::new(
        "subpd",
        0x5C,
        SsePfx::p66(),
        OpEnc::RM,
        SseCategory::Arithmetic,
        "Subtract Packed Double-FP",
    ),
    SseInstr::new(
        "minpd",
        0x5D,
        SsePfx::p66(),
        OpEnc::RM,
        SseCategory::Arithmetic,
        "Return Minimum Packed Double-FP",
    ),
    SseInstr::new(
        "divpd",
        0x5E,
        SsePfx::p66(),
        OpEnc::RM,
        SseCategory::Arithmetic,
        "Divide Packed Double-FP",
    ),
    SseInstr::new(
        "maxpd",
        0x5F,
        SsePfx::p66(),
        OpEnc::RM,
        SseCategory::Arithmetic,
        "Return Maximum Packed Double-FP",
    ),
    // 0x60-0x6F â€” MMX/SSE2 integer pack/unpack (require 66 in SSE2)
    SseInstr::new(
        "punpcklbw",
        0x60,
        SsePfx::p66(),
        OpEnc::RM,
        SseCategory::Pack,
        "Unpack Low Data Bytes",
    ),
    SseInstr::new(
        "punpcklwd",
        0x61,
        SsePfx::p66(),
        OpEnc::RM,
        SseCategory::Pack,
        "Unpack Low Data Words",
    ),
    SseInstr::new(
        "punpckldq",
        0x62,
        SsePfx::p66(),
        OpEnc::RM,
        SseCategory::Pack,
        "Unpack Low Data DWords",
    ),
    SseInstr::new(
        "packsswb",
        0x63,
        SsePfx::p66(),
        OpEnc::RM,
        SseCategory::Pack,
        "Pack with Signed Saturation Words to Bytes",
    ),
    SseInstr::new(
        "pcmpgtb",
        0x64,
        SsePfx::p66(),
        OpEnc::RM,
        SseCategory::Compare,
        "Compare Packed Signed Byte Integers for Greater Than",
    ),
    SseInstr::new(
        "pcmpgtw",
        0x65,
        SsePfx::p66(),
        OpEnc::RM,
        SseCategory::Compare,
        "Compare Packed Signed Word Integers for Greater Than",
    ),
    SseInstr::new(
        "pcmpgtd",
        0x66,
        SsePfx::p66(),
        OpEnc::RM,
        SseCategory::Compare,
        "Compare Packed Signed DW Integers for Greater Than",
    ),
    SseInstr::new(
        "packuswb",
        0x67,
        SsePfx::p66(),
        OpEnc::RM,
        SseCategory::Pack,
        "Pack Unsigned Saturation Words to Bytes",
    ),
    SseInstr::new(
        "punpckhbw",
        0x68,
        SsePfx::p66(),
        OpEnc::RM,
        SseCategory::Pack,
        "Unpack High Data Bytes",
    ),
    SseInstr::new(
        "punpckhwd",
        0x69,
        SsePfx::p66(),
        OpEnc::RM,
        SseCategory::Pack,
        "Unpack High Data Words",
    ),
    SseInstr::new(
        "punpckhdq",
        0x6A,
        SsePfx::p66(),
        OpEnc::RM,
        SseCategory::Pack,
        "Unpack High Data DWords",
    ),
    SseInstr::new(
        "packssdw",
        0x6B,
        SsePfx::p66(),
        OpEnc::RM,
        SseCategory::Pack,
        "Pack with Signed Saturation DWords to Words",
    ),
    SseInstr::new(
        "punpcklqdq",
        0x6C,
        SsePfx::p66(),
        OpEnc::RM,
        SseCategory::Pack,
        "Unpack Low QWords",
    ),
    SseInstr::new(
        "punpckhqdq",
        0x6D,
        SsePfx::p66(),
        OpEnc::RM,
        SseCategory::Pack,
        "Unpack High QWords",
    ),
    SseInstr::new(
        "movd",
        0x6E,
        SsePfx::p66(),
        OpEnc::RM,
        SseCategory::Move,
        "Move DWord (or QWord with REX.W)",
    ),
    SseInstr::new(
        "movdqa",
        0x6F,
        SsePfx::p66(),
        OpEnc::RM,
        SseCategory::Move,
        "Move Aligned DQWord",
    ),
    SseInstr::new(
        "pshufd",
        0x70,
        SsePfx::p66(),
        OpEnc::RMV,
        SseCategory::Shuffle,
        "Shuffle Packed DWords",
    ),
    SseInstr::new(
        "pcmpeqb",
        0x74,
        SsePfx::p66(),
        OpEnc::RM,
        SseCategory::Compare,
        "Compare Packed Bytes for Equality",
    ),
    SseInstr::new(
        "pcmpeqw",
        0x75,
        SsePfx::p66(),
        OpEnc::RM,
        SseCategory::Compare,
        "Compare Packed Words for Equality",
    ),
    SseInstr::new(
        "pcmpeqd",
        0x76,
        SsePfx::p66(),
        OpEnc::RM,
        SseCategory::Compare,
        "Compare Packed DWords for Equality",
    ),
    SseInstr::new(
        "movd",
        0x7E,
        SsePfx::p66(),
        OpEnc::MR,
        SseCategory::Move,
        "Move DWord (store)",
    ),
    SseInstr::new(
        "movdqa",
        0x7F,
        SsePfx::p66(),
        OpEnc::MR,
        SseCategory::Move,
        "Move Aligned DQWord (store)",
    ),
    SseInstr::new(
        "haddpd",
        0x7C,
        SsePfx::p66(),
        OpEnc::RM,
        SseCategory::HorizontalArith,
        "Horizontal Add Packed Double-FP",
    ),
    SseInstr::new(
        "hsubpd",
        0x7D,
        SsePfx::p66(),
        OpEnc::RM,
        SseCategory::HorizontalArith,
        "Horizontal Subtract Packed Double-FP",
    ),
    SseInstr::new(
        "cmppd",
        0xC2,
        SsePfx::p66(),
        OpEnc::RMV,
        SseCategory::Compare,
        "Compare Packed Double-FP",
    ),
    SseInstr::new(
        "shufpd",
        0xC6,
        SsePfx::p66(),
        OpEnc::RMV,
        SseCategory::Shuffle,
        "Shuffle Packed Double-FP",
    ),
    // Integer arithmetic
    SseInstr::new(
        "paddb",
        0xFC,
        SsePfx::p66(),
        OpEnc::RM,
        SseCategory::Arithmetic,
        "Add Packed Byte Integers",
    ),
    SseInstr::new(
        "paddw",
        0xFD,
        SsePfx::p66(),
        OpEnc::RM,
        SseCategory::Arithmetic,
        "Add Packed Word Integers",
    ),
    SseInstr::new(
        "paddd",
        0xFE,
        SsePfx::p66(),
        OpEnc::RM,
        SseCategory::Arithmetic,
        "Add Packed DWord Integers",
    ),
    SseInstr::new(
        "paddq",
        0xD4,
        SsePfx::p66(),
        OpEnc::RM,
        SseCategory::Arithmetic,
        "Add Packed QWord Integers",
    ),
    SseInstr::new(
        "psubb",
        0xF8,
        SsePfx::p66(),
        OpEnc::RM,
        SseCategory::Arithmetic,
        "Subtract Packed Byte Integers",
    ),
    SseInstr::new(
        "psubw",
        0xF9,
        SsePfx::p66(),
        OpEnc::RM,
        SseCategory::Arithmetic,
        "Subtract Packed Word Integers",
    ),
    SseInstr::new(
        "psubd",
        0xFA,
        SsePfx::p66(),
        OpEnc::RM,
        SseCategory::Arithmetic,
        "Subtract Packed DWord Integers",
    ),
    SseInstr::new(
        "psubq",
        0xFB,
        SsePfx::p66(),
        OpEnc::RM,
        SseCategory::Arithmetic,
        "Subtract Packed QWord Integers",
    ),
    SseInstr::new(
        "pmullw",
        0xD5,
        SsePfx::p66(),
        OpEnc::RM,
        SseCategory::Arithmetic,
        "Multiply Packed Signed Word Integers, Store Low",
    ),
    SseInstr::new(
        "pmulhw",
        0xE5,
        SsePfx::p66(),
        OpEnc::RM,
        SseCategory::Arithmetic,
        "Multiply Packed Signed Word Integers, Store High",
    ),
    SseInstr::new(
        "pmulhuw",
        0xE4,
        SsePfx::p66(),
        OpEnc::RM,
        SseCategory::Arithmetic,
        "Multiply Packed Unsigned Word Integers, Store High",
    ),
    SseInstr::new(
        "pmuludq",
        0xF4,
        SsePfx::p66(),
        OpEnc::RM,
        SseCategory::Arithmetic,
        "Multiply Packed Unsigned DW Integers",
    ),
    SseInstr::new(
        "pmaddwd",
        0xF5,
        SsePfx::p66(),
        OpEnc::RM,
        SseCategory::Arithmetic,
        "Multiply and Add Packed Integers",
    ),
    SseInstr::new(
        "pand",
        0xDB,
        SsePfx::p66(),
        OpEnc::RM,
        SseCategory::Logical,
        "Logical AND",
    ),
    SseInstr::new(
        "pandn",
        0xDF,
        SsePfx::p66(),
        OpEnc::RM,
        SseCategory::Logical,
        "Logical AND NOT",
    ),
    SseInstr::new(
        "por",
        0xEB,
        SsePfx::p66(),
        OpEnc::RM,
        SseCategory::Logical,
        "Logical OR",
    ),
    SseInstr::new(
        "pxor",
        0xEF,
        SsePfx::p66(),
        OpEnc::RM,
        SseCategory::Logical,
        "Logical XOR",
    ),
    SseInstr::new(
        "psrlw",
        0xD1,
        SsePfx::p66(),
        OpEnc::RM,
        SseCategory::Shift,
        "Shift Packed Words Right Logical",
    ),
    SseInstr::new(
        "psrld",
        0xD2,
        SsePfx::p66(),
        OpEnc::RM,
        SseCategory::Shift,
        "Shift Packed DWords Right Logical",
    ),
    SseInstr::new(
        "psrlq",
        0xD3,
        SsePfx::p66(),
        OpEnc::RM,
        SseCategory::Shift,
        "Shift Packed QWords Right Logical",
    ),
    SseInstr::new(
        "psraw",
        0xE1,
        SsePfx::p66(),
        OpEnc::RM,
        SseCategory::Shift,
        "Shift Packed Words Right Arithmetic",
    ),
    SseInstr::new(
        "psrad",
        0xE2,
        SsePfx::p66(),
        OpEnc::RM,
        SseCategory::Shift,
        "Shift Packed DWords Right Arithmetic",
    ),
    SseInstr::new(
        "psllw",
        0xF1,
        SsePfx::p66(),
        OpEnc::RM,
        SseCategory::Shift,
        "Shift Packed Words Left Logical",
    ),
    SseInstr::new(
        "pslld",
        0xF2,
        SsePfx::p66(),
        OpEnc::RM,
        SseCategory::Shift,
        "Shift Packed DWords Left Logical",
    ),
    SseInstr::new(
        "psllq",
        0xF3,
        SsePfx::p66(),
        OpEnc::RM,
        SseCategory::Shift,
        "Shift Packed QWords Left Logical",
    ),
    SseInstr::new(
        "psrldq",
        0x73,
        SsePfx::p66(),
        OpEnc::MI,
        SseCategory::Shift,
        "Shift DQWord Right Logical (imm8 bytes)",
    ),
    SseInstr::new(
        "pslldq",
        0x73,
        SsePfx::p66(),
        OpEnc::MI,
        SseCategory::Shift,
        "Shift DQWord Left Logical (imm8 bytes)",
    ),
    SseInstr::new(
        "movntdq",
        0xE7,
        SsePfx::p66(),
        OpEnc::MR,
        SseCategory::Cache,
        "Store DQWord Non-Temporal",
    ),
    SseInstr::new(
        "movdq2q",
        0xD6,
        SsePfx::p66(),
        OpEnc::MR,
        SseCategory::Move,
        "Move QWord from XMM to MMX",
    ),
    SseInstr::new(
        "movq2dq",
        0xD6,
        SsePfx::pf3(),
        OpEnc::RM,
        SseCategory::Move,
        "Move QWord from MMX to XMM",
    ),
    SseInstr::new(
        "cvtdq2pd",
        0xE6,
        SsePfx::pf3(),
        OpEnc::RM,
        SseCategory::Convert,
        "Convert Packed DW Int to Packed Double-FP",
    ),
    SseInstr::new(
        "cvtpd2dq",
        0xE6,
        SsePfx::pf2(),
        OpEnc::RM,
        SseCategory::Convert,
        "Convert Packed Double-FP to DW Int",
    ),
    SseInstr::new(
        "cvttpd2dq",
        0xE6,
        SsePfx::p66(),
        OpEnc::RM,
        SseCategory::Convert,
        "Convert with Truncation Packed Double-FP to DW Int",
    ),
];

// ---------------------------------------------------------------------------
// SSE (scalar single) â€” F3h prefix
// ---------------------------------------------------------------------------

/// SSE scalar single-precision (F3 0F xx).
pub static SSE_F3: &[SseInstr] = &[
    SseInstr::new(
        "movss",
        0x10,
        SsePfx::pf3(),
        OpEnc::RM,
        SseCategory::Move,
        "Move Scalar Single-FP (load)",
    ),
    SseInstr::new(
        "movss",
        0x11,
        SsePfx::pf3(),
        OpEnc::MR,
        SseCategory::Move,
        "Move Scalar Single-FP (store)",
    ),
    SseInstr::new(
        "movsldup",
        0x12,
        SsePfx::pf3(),
        OpEnc::RM,
        SseCategory::Move,
        "Move and Duplicate Low Single-FP",
    ),
    SseInstr::new(
        "movshdup",
        0x16,
        SsePfx::pf3(),
        OpEnc::RM,
        SseCategory::Move,
        "Move and Duplicate High Single-FP",
    ),
    SseInstr::new(
        "cvtsi2ss",
        0x2A,
        SsePfx::pf3(),
        OpEnc::RM,
        SseCategory::Convert,
        "Convert Integer to Scalar Single-FP",
    ),
    SseInstr::new(
        "cvttss2si",
        0x2C,
        SsePfx::pf3(),
        OpEnc::RM,
        SseCategory::Convert,
        "Convert with Truncation Scalar Single-FP to Integer",
    ),
    SseInstr::new(
        "cvtss2si",
        0x2D,
        SsePfx::pf3(),
        OpEnc::RM,
        SseCategory::Convert,
        "Convert Scalar Single-FP to Integer",
    ),
    SseInstr::new(
        "sqrtss",
        0x51,
        SsePfx::pf3(),
        OpEnc::RM,
        SseCategory::Arithmetic,
        "Square Root Scalar Single-FP",
    ),
    SseInstr::new(
        "rsqrtss",
        0x52,
        SsePfx::pf3(),
        OpEnc::RM,
        SseCategory::Arithmetic,
        "Reciprocal Square Root Scalar Single-FP",
    ),
    SseInstr::new(
        "rcpss",
        0x53,
        SsePfx::pf3(),
        OpEnc::RM,
        SseCategory::Arithmetic,
        "Reciprocal Scalar Single-FP",
    ),
    SseInstr::new(
        "addss",
        0x58,
        SsePfx::pf3(),
        OpEnc::RM,
        SseCategory::Arithmetic,
        "Add Scalar Single-FP",
    ),
    SseInstr::new(
        "mulss",
        0x59,
        SsePfx::pf3(),
        OpEnc::RM,
        SseCategory::Arithmetic,
        "Multiply Scalar Single-FP",
    ),
    SseInstr::new(
        "cvtss2sd",
        0x5A,
        SsePfx::pf3(),
        OpEnc::RM,
        SseCategory::Convert,
        "Convert Scalar Single-FP to Double-FP",
    ),
    SseInstr::new(
        "cvttps2dq",
        0x5B,
        SsePfx::pf3(),
        OpEnc::RM,
        SseCategory::Convert,
        "Convert with Truncation Packed Single-FP to DW Int",
    ),
    SseInstr::new(
        "subss",
        0x5C,
        SsePfx::pf3(),
        OpEnc::RM,
        SseCategory::Arithmetic,
        "Subtract Scalar Single-FP",
    ),
    SseInstr::new(
        "minss",
        0x5D,
        SsePfx::pf3(),
        OpEnc::RM,
        SseCategory::Arithmetic,
        "Return Minimum Scalar Single-FP",
    ),
    SseInstr::new(
        "divss",
        0x5E,
        SsePfx::pf3(),
        OpEnc::RM,
        SseCategory::Arithmetic,
        "Divide Scalar Single-FP",
    ),
    SseInstr::new(
        "maxss",
        0x5F,
        SsePfx::pf3(),
        OpEnc::RM,
        SseCategory::Arithmetic,
        "Return Maximum Scalar Single-FP",
    ),
    SseInstr::new(
        "cmpss",
        0xC2,
        SsePfx::pf3(),
        OpEnc::RMV,
        SseCategory::Compare,
        "Compare Scalar Single-FP",
    ),
    SseInstr::new(
        "movdqu",
        0x6F,
        SsePfx::pf3(),
        OpEnc::RM,
        SseCategory::Move,
        "Move Unaligned DQWord",
    ),
    SseInstr::new(
        "pshufhw",
        0x70,
        SsePfx::pf3(),
        OpEnc::RMV,
        SseCategory::Shuffle,
        "Shuffle High Words",
    ),
    SseInstr::new(
        "movdqu",
        0x7F,
        SsePfx::pf3(),
        OpEnc::MR,
        SseCategory::Move,
        "Move Unaligned DQWord (store)",
    ),
    SseInstr::new(
        "lddqu",
        0xF0,
        SsePfx::pf3(),
        OpEnc::RM,
        SseCategory::Move,
        "Load Unaligned Integer 128 Bits (SSE3)",
    ),
];

// ---------------------------------------------------------------------------
// SSE (scalar double) â€” F2h prefix
// ---------------------------------------------------------------------------

/// SSE scalar double-precision (F2 0F xx).
pub static SSE_F2: &[SseInstr] = &[
    SseInstr::new(
        "movsd",
        0x10,
        SsePfx::pf2(),
        OpEnc::RM,
        SseCategory::Move,
        "Move Scalar Double-FP (load)",
    ),
    SseInstr::new(
        "movsd",
        0x11,
        SsePfx::pf2(),
        OpEnc::MR,
        SseCategory::Move,
        "Move Scalar Double-FP (store)",
    ),
    SseInstr::new(
        "movddup",
        0x12,
        SsePfx::pf2(),
        OpEnc::RM,
        SseCategory::Move,
        "Move and Duplicate Double-FP (SSE3)",
    ),
    SseInstr::new(
        "cvtsi2sd",
        0x2A,
        SsePfx::pf2(),
        OpEnc::RM,
        SseCategory::Convert,
        "Convert Integer to Scalar Double-FP",
    ),
    SseInstr::new(
        "cvttsd2si",
        0x2C,
        SsePfx::pf2(),
        OpEnc::RM,
        SseCategory::Convert,
        "Convert with Truncation Scalar Double-FP to Integer",
    ),
    SseInstr::new(
        "cvtsd2si",
        0x2D,
        SsePfx::pf2(),
        OpEnc::RM,
        SseCategory::Convert,
        "Convert Scalar Double-FP to Integer",
    ),
    SseInstr::new(
        "sqrtsd",
        0x51,
        SsePfx::pf2(),
        OpEnc::RM,
        SseCategory::Arithmetic,
        "Square Root Scalar Double-FP",
    ),
    SseInstr::new(
        "addsd",
        0x58,
        SsePfx::pf2(),
        OpEnc::RM,
        SseCategory::Arithmetic,
        "Add Scalar Double-FP",
    ),
    SseInstr::new(
        "mulsd",
        0x59,
        SsePfx::pf2(),
        OpEnc::RM,
        SseCategory::Arithmetic,
        "Multiply Scalar Double-FP",
    ),
    SseInstr::new(
        "cvtsd2ss",
        0x5A,
        SsePfx::pf2(),
        OpEnc::RM,
        SseCategory::Convert,
        "Convert Scalar Double-FP to Single-FP",
    ),
    SseInstr::new(
        "subsd",
        0x5C,
        SsePfx::pf2(),
        OpEnc::RM,
        SseCategory::Arithmetic,
        "Subtract Scalar Double-FP",
    ),
    SseInstr::new(
        "minsd",
        0x5D,
        SsePfx::pf2(),
        OpEnc::RM,
        SseCategory::Arithmetic,
        "Return Minimum Scalar Double-FP",
    ),
    SseInstr::new(
        "divsd",
        0x5E,
        SsePfx::pf2(),
        OpEnc::RM,
        SseCategory::Arithmetic,
        "Divide Scalar Double-FP",
    ),
    SseInstr::new(
        "maxsd",
        0x5F,
        SsePfx::pf2(),
        OpEnc::RM,
        SseCategory::Arithmetic,
        "Return Maximum Scalar Double-FP",
    ),
    SseInstr::new(
        "cmpsd",
        0xC2,
        SsePfx::pf2(),
        OpEnc::RMV,
        SseCategory::Compare,
        "Compare Scalar Double-FP",
    ),
    SseInstr::new(
        "pshuflw",
        0x70,
        SsePfx::pf2(),
        OpEnc::RMV,
        SseCategory::Shuffle,
        "Shuffle Low Words",
    ),
    SseInstr::new(
        "haddps",
        0x7C,
        SsePfx::pf2(),
        OpEnc::RM,
        SseCategory::HorizontalArith,
        "Horizontal Add Packed Single-FP (SSE3)",
    ),
    SseInstr::new(
        "hsubps",
        0x7D,
        SsePfx::pf2(),
        OpEnc::RM,
        SseCategory::HorizontalArith,
        "Horizontal Subtract Packed Single-FP (SSE3)",
    ),
    SseInstr::new(
        "addsubps",
        0xD0,
        SsePfx::pf2(),
        OpEnc::RM,
        SseCategory::Arithmetic,
        "Add/Subtract Packed Single-FP (SSE3)",
    ),
];

// ---------------------------------------------------------------------------
// SSSE3 â€” 0F 38 xx with optional 66h
// ---------------------------------------------------------------------------

/// SSSE3 instructions (0F38 prefix).
pub static SSSE3: &[SseInstr] = &[
    SseInstr::new(
        "pshufb",
        0x00,
        SsePfx::p66(),
        OpEnc::RM,
        SseCategory::Shuffle,
        "Packed Shuffle Bytes",
    ),
    SseInstr::new(
        "phaddw",
        0x01,
        SsePfx::p66(),
        OpEnc::RM,
        SseCategory::HorizontalArith,
        "Packed Horizontal Add Words",
    ),
    SseInstr::new(
        "phaddd",
        0x02,
        SsePfx::p66(),
        OpEnc::RM,
        SseCategory::HorizontalArith,
        "Packed Horizontal Add DWords",
    ),
    SseInstr::new(
        "phaddsw",
        0x03,
        SsePfx::p66(),
        OpEnc::RM,
        SseCategory::HorizontalArith,
        "Packed Horizontal Add and Saturate Words",
    ),
    SseInstr::new(
        "pmaddubsw",
        0x04,
        SsePfx::p66(),
        OpEnc::RM,
        SseCategory::Arithmetic,
        "Multiply and Add Packed Unsigned/Signed Bytes",
    ),
    SseInstr::new(
        "phsubw",
        0x05,
        SsePfx::p66(),
        OpEnc::RM,
        SseCategory::HorizontalArith,
        "Packed Horizontal Subtract Words",
    ),
    SseInstr::new(
        "phsubd",
        0x06,
        SsePfx::p66(),
        OpEnc::RM,
        SseCategory::HorizontalArith,
        "Packed Horizontal Subtract DWords",
    ),
    SseInstr::new(
        "phsubsw",
        0x07,
        SsePfx::p66(),
        OpEnc::RM,
        SseCategory::HorizontalArith,
        "Packed Horizontal Subtract and Saturate Words",
    ),
    SseInstr::new(
        "psignb",
        0x08,
        SsePfx::p66(),
        OpEnc::RM,
        SseCategory::Arithmetic,
        "Packed SIGN Bytes",
    ),
    SseInstr::new(
        "psignw",
        0x09,
        SsePfx::p66(),
        OpEnc::RM,
        SseCategory::Arithmetic,
        "Packed SIGN Words",
    ),
    SseInstr::new(
        "psignd",
        0x0A,
        SsePfx::p66(),
        OpEnc::RM,
        SseCategory::Arithmetic,
        "Packed SIGN DWords",
    ),
    SseInstr::new(
        "pmulhrsw",
        0x0B,
        SsePfx::p66(),
        OpEnc::RM,
        SseCategory::Arithmetic,
        "Packed Multiply High with Round and Scale Words",
    ),
    SseInstr::new(
        "permps",
        0x0C,
        SsePfx::p66(),
        OpEnc::RM,
        SseCategory::Shuffle,
        "Permute Packed Single-FP Elements",
    ),
    SseInstr::new(
        "permd",
        0x36,
        SsePfx::p66(),
        OpEnc::RM,
        SseCategory::Shuffle,
        "Permute Packed DW Elements",
    ),
    SseInstr::new(
        "pabsb",
        0x1C,
        SsePfx::p66(),
        OpEnc::RM,
        SseCategory::Arithmetic,
        "Packed Absolute Value Bytes",
    ),
    SseInstr::new(
        "pabsw",
        0x1D,
        SsePfx::p66(),
        OpEnc::RM,
        SseCategory::Arithmetic,
        "Packed Absolute Value Words",
    ),
    SseInstr::new(
        "pabsd",
        0x1E,
        SsePfx::p66(),
        OpEnc::RM,
        SseCategory::Arithmetic,
        "Packed Absolute Value DWords",
    ),
    SseInstr::new(
        "palignr",
        0x0F,
        SsePfx::p66(),
        OpEnc::RMV,
        SseCategory::Shuffle,
        "Packed Align Right",
    ),
];

// ---------------------------------------------------------------------------
// SSE4.1 â€” 0F 38 xx with 66h
// ---------------------------------------------------------------------------

/// SSE4.1 instructions (0F38 prefix, 66h mandatory).
pub static SSE41: &[SseInstr] = &[
    SseInstr::new(
        "pblendvb",
        0x10,
        SsePfx::p66(),
        OpEnc::RM,
        SseCategory::BlendInsertExtract,
        "Variable Blend Packed Bytes",
    ),
    SseInstr::new(
        "blendvps",
        0x14,
        SsePfx::p66(),
        OpEnc::RM,
        SseCategory::BlendInsertExtract,
        "Variable Blend Packed Single-FP",
    ),
    SseInstr::new(
        "blendvpd",
        0x15,
        SsePfx::p66(),
        OpEnc::RM,
        SseCategory::BlendInsertExtract,
        "Variable Blend Packed Double-FP",
    ),
    SseInstr::new(
        "ptest",
        0x17,
        SsePfx::p66(),
        OpEnc::RM,
        SseCategory::Compare,
        "Logical Compare",
    ),
    SseInstr::new(
        "pmovsxbw",
        0x20,
        SsePfx::p66(),
        OpEnc::RM,
        SseCategory::Convert,
        "Packed Move with Sign Extend Bytes to Words",
    ),
    SseInstr::new(
        "pmovsxbd",
        0x21,
        SsePfx::p66(),
        OpEnc::RM,
        SseCategory::Convert,
        "Packed Move with Sign Extend Bytes to DWords",
    ),
    SseInstr::new(
        "pmovsxbq",
        0x22,
        SsePfx::p66(),
        OpEnc::RM,
        SseCategory::Convert,
        "Packed Move with Sign Extend Bytes to QWords",
    ),
    SseInstr::new(
        "pmovsxwd",
        0x23,
        SsePfx::p66(),
        OpEnc::RM,
        SseCategory::Convert,
        "Packed Move with Sign Extend Words to DWords",
    ),
    SseInstr::new(
        "pmovsxwq",
        0x24,
        SsePfx::p66(),
        OpEnc::RM,
        SseCategory::Convert,
        "Packed Move with Sign Extend Words to QWords",
    ),
    SseInstr::new(
        "pmovsxdq",
        0x25,
        SsePfx::p66(),
        OpEnc::RM,
        SseCategory::Convert,
        "Packed Move with Sign Extend DWords to QWords",
    ),
    SseInstr::new(
        "pmuldq",
        0x28,
        SsePfx::p66(),
        OpEnc::RM,
        SseCategory::Arithmetic,
        "Multiply Packed Signed DWord Integers",
    ),
    SseInstr::new(
        "pcmpeqq",
        0x29,
        SsePfx::p66(),
        OpEnc::RM,
        SseCategory::Compare,
        "Compare Packed QWord Data for Equal",
    ),
    SseInstr::new(
        "movntdqa",
        0x2A,
        SsePfx::p66(),
        OpEnc::RM,
        SseCategory::Cache,
        "Load DQWord Non-Temporal Aligned Hint",
    ),
    SseInstr::new(
        "packusdw",
        0x2B,
        SsePfx::p66(),
        OpEnc::RM,
        SseCategory::Pack,
        "Pack with Unsigned Saturation DWords to Words",
    ),
    SseInstr::new(
        "pmovzxbw",
        0x30,
        SsePfx::p66(),
        OpEnc::RM,
        SseCategory::Convert,
        "Packed Move with Zero Extend Bytes to Words",
    ),
    SseInstr::new(
        "pmovzxbd",
        0x31,
        SsePfx::p66(),
        OpEnc::RM,
        SseCategory::Convert,
        "Packed Move with Zero Extend Bytes to DWords",
    ),
    SseInstr::new(
        "pmovzxbq",
        0x32,
        SsePfx::p66(),
        OpEnc::RM,
        SseCategory::Convert,
        "Packed Move with Zero Extend Bytes to QWords",
    ),
    SseInstr::new(
        "pmovzxwd",
        0x33,
        SsePfx::p66(),
        OpEnc::RM,
        SseCategory::Convert,
        "Packed Move with Zero Extend Words to DWords",
    ),
    SseInstr::new(
        "pmovzxwq",
        0x34,
        SsePfx::p66(),
        OpEnc::RM,
        SseCategory::Convert,
        "Packed Move with Zero Extend Words to QWords",
    ),
    SseInstr::new(
        "pmovzxdq",
        0x35,
        SsePfx::p66(),
        OpEnc::RM,
        SseCategory::Convert,
        "Packed Move with Zero Extend DWords to QWords",
    ),
    SseInstr::new(
        "pcmpeqq",
        0x29,
        SsePfx::p66(),
        OpEnc::RM,
        SseCategory::Compare,
        "Compare Packed QWords for Equality",
    ),
    SseInstr::new(
        "pminsb",
        0x38,
        SsePfx::p66(),
        OpEnc::RM,
        SseCategory::Arithmetic,
        "Minimum of Packed Signed Byte Integers",
    ),
    SseInstr::new(
        "pminsd",
        0x39,
        SsePfx::p66(),
        OpEnc::RM,
        SseCategory::Arithmetic,
        "Minimum of Packed Signed DWord Integers",
    ),
    SseInstr::new(
        "pminuw",
        0x3A,
        SsePfx::p66(),
        OpEnc::RM,
        SseCategory::Arithmetic,
        "Minimum of Packed Unsigned Word Integers",
    ),
    SseInstr::new(
        "pminud",
        0x3B,
        SsePfx::p66(),
        OpEnc::RM,
        SseCategory::Arithmetic,
        "Minimum of Packed Unsigned DWord Integers",
    ),
    SseInstr::new(
        "pmaxsb",
        0x3C,
        SsePfx::p66(),
        OpEnc::RM,
        SseCategory::Arithmetic,
        "Maximum of Packed Signed Byte Integers",
    ),
    SseInstr::new(
        "pmaxsd",
        0x3D,
        SsePfx::p66(),
        OpEnc::RM,
        SseCategory::Arithmetic,
        "Maximum of Packed Signed DWord Integers",
    ),
    SseInstr::new(
        "pmaxuw",
        0x3E,
        SsePfx::p66(),
        OpEnc::RM,
        SseCategory::Arithmetic,
        "Maximum of Packed Unsigned Word Integers",
    ),
    SseInstr::new(
        "pmaxud",
        0x3F,
        SsePfx::p66(),
        OpEnc::RM,
        SseCategory::Arithmetic,
        "Maximum of Packed Unsigned DWord Integers",
    ),
    SseInstr::new(
        "pmulld",
        0x40,
        SsePfx::p66(),
        OpEnc::RM,
        SseCategory::Arithmetic,
        "Multiply Packed Signed DWord Integers (Low result)",
    ),
    SseInstr::new(
        "phminposuw",
        0x41,
        SsePfx::p66(),
        OpEnc::RM,
        SseCategory::Arithmetic,
        "Packed Horizontal Word Minimum",
    ),
    SseInstr::new(
        "aesimc",
        0xDB,
        SsePfx::p66(),
        OpEnc::RM,
        SseCategory::Crypto,
        "AES Inverse Mix Columns",
    ),
    SseInstr::new(
        "aesenc",
        0xDC,
        SsePfx::p66(),
        OpEnc::RM,
        SseCategory::Crypto,
        "AES Round Encryption",
    ),
    SseInstr::new(
        "aesenclast",
        0xDD,
        SsePfx::p66(),
        OpEnc::RM,
        SseCategory::Crypto,
        "AES Last Round Encryption",
    ),
    SseInstr::new(
        "aesdec",
        0xDE,
        SsePfx::p66(),
        OpEnc::RM,
        SseCategory::Crypto,
        "AES Round Decryption",
    ),
    SseInstr::new(
        "aesdeclast",
        0xDF,
        SsePfx::p66(),
        OpEnc::RM,
        SseCategory::Crypto,
        "AES Last Round Decryption",
    ),
];

// ---------------------------------------------------------------------------
// SSE4.1 â€” 0F 3A xx imm8 with 66h
// ---------------------------------------------------------------------------

/// SSE4.1 instructions requiring 0F3A escape.
pub static SSE41_3A: &[SseInstr] = &[
    SseInstr::new(
        "roundps",
        0x08,
        SsePfx::p66(),
        OpEnc::RMV,
        SseCategory::Arithmetic,
        "Round Packed Single-FP",
    ),
    SseInstr::new(
        "roundpd",
        0x09,
        SsePfx::p66(),
        OpEnc::RMV,
        SseCategory::Arithmetic,
        "Round Packed Double-FP",
    ),
    SseInstr::new(
        "roundss",
        0x0A,
        SsePfx::p66(),
        OpEnc::RMV,
        SseCategory::Arithmetic,
        "Round Scalar Single-FP",
    ),
    SseInstr::new(
        "roundsd",
        0x0B,
        SsePfx::p66(),
        OpEnc::RMV,
        SseCategory::Arithmetic,
        "Round Scalar Double-FP",
    ),
    SseInstr::new(
        "blendps",
        0x0C,
        SsePfx::p66(),
        OpEnc::RMV,
        SseCategory::BlendInsertExtract,
        "Blend Packed Single-FP",
    ),
    SseInstr::new(
        "blendpd",
        0x0D,
        SsePfx::p66(),
        OpEnc::RMV,
        SseCategory::BlendInsertExtract,
        "Blend Packed Double-FP",
    ),
    SseInstr::new(
        "pblendw",
        0x0E,
        SsePfx::p66(),
        OpEnc::RMV,
        SseCategory::BlendInsertExtract,
        "Blend Packed Words",
    ),
    SseInstr::new(
        "palignr",
        0x0F,
        SsePfx::p66(),
        OpEnc::RMV,
        SseCategory::Shuffle,
        "Packed Align Right",
    ),
    SseInstr::new(
        "pextrb",
        0x14,
        SsePfx::p66(),
        OpEnc::MR,
        SseCategory::BlendInsertExtract,
        "Extract Byte",
    ),
    SseInstr::new(
        "pextrd",
        0x16,
        SsePfx::p66(),
        OpEnc::MR,
        SseCategory::BlendInsertExtract,
        "Extract DWord",
    ),
    SseInstr::new(
        "extractps",
        0x17,
        SsePfx::p66(),
        OpEnc::MR,
        SseCategory::BlendInsertExtract,
        "Extract Packed Single-FP",
    ),
    SseInstr::new(
        "pinsrb",
        0x20,
        SsePfx::p66(),
        OpEnc::RM,
        SseCategory::BlendInsertExtract,
        "Insert Byte",
    ),
    SseInstr::new(
        "insertps",
        0x21,
        SsePfx::p66(),
        OpEnc::RMV,
        SseCategory::BlendInsertExtract,
        "Insert Packed Single-FP",
    ),
    SseInstr::new(
        "pinsrd",
        0x22,
        SsePfx::p66(),
        OpEnc::RM,
        SseCategory::BlendInsertExtract,
        "Insert DWord",
    ),
    SseInstr::new(
        "dpps",
        0x40,
        SsePfx::p66(),
        OpEnc::RMV,
        SseCategory::HorizontalArith,
        "Dot Product Packed Single-FP",
    ),
    SseInstr::new(
        "dppd",
        0x41,
        SsePfx::p66(),
        OpEnc::RMV,
        SseCategory::HorizontalArith,
        "Dot Product Packed Double-FP",
    ),
    SseInstr::new(
        "mpsadbw",
        0x42,
        SsePfx::p66(),
        OpEnc::RMV,
        SseCategory::Arithmetic,
        "Compute Multiple Packed Sums of Absolute Difference",
    ),
    SseInstr::new(
        "pclmulqdq",
        0x44,
        SsePfx::p66(),
        OpEnc::RMV,
        SseCategory::Crypto,
        "Carry-Less Multiplication QWord",
    ),
    SseInstr::new(
        "pcmpestrm",
        0x60,
        SsePfx::p66(),
        OpEnc::RMV,
        SseCategory::StringText,
        "Packed Compare Explicit Length Strings, Return Mask",
    ),
    SseInstr::new(
        "pcmpestri",
        0x61,
        SsePfx::p66(),
        OpEnc::RMV,
        SseCategory::StringText,
        "Packed Compare Explicit Length Strings, Return Index",
    ),
    SseInstr::new(
        "pcmpistrm",
        0x62,
        SsePfx::p66(),
        OpEnc::RMV,
        SseCategory::StringText,
        "Packed Compare Implicit Length Strings, Return Mask",
    ),
    SseInstr::new(
        "pcmpistri",
        0x63,
        SsePfx::p66(),
        OpEnc::RMV,
        SseCategory::StringText,
        "Packed Compare Implicit Length Strings, Return Index",
    ),
    SseInstr::new(
        "aeskeygenassist",
        0xDF,
        SsePfx::p66(),
        OpEnc::RMV,
        SseCategory::Crypto,
        "AES Round Key Generation Assist",
    ),
];

// ---------------------------------------------------------------------------
// SSE4.2 â€” 0F 38 xx with 66h (separate from 3A)
// ---------------------------------------------------------------------------

/// SSE4.2 instructions (0F38 prefix, 66h mandatory).
pub static SSE42: &[SseInstr] = &[
    SseInstr::new(
        "pcmpgtq",
        0x37,
        SsePfx::p66(),
        OpEnc::RM,
        SseCategory::Compare,
        "Compare Packed QWords for Greater Than",
    ),
    SseInstr::new(
        "crc32",
        0xF0,
        SsePfx::pf2(),
        OpEnc::RM,
        SseCategory::Crc,
        "Accumulate CRC32 Value (byte source, F2 prefix)",
    ),
    SseInstr::new(
        "crc32",
        0xF1,
        SsePfx::pf2(),
        OpEnc::RM,
        SseCategory::Crc,
        "Accumulate CRC32 Value (word/dword/qword source)",
    ),
];

// ---------------------------------------------------------------------------
// Lookup helpers
// ---------------------------------------------------------------------------

/// Find the SSE descriptor for a given opcode byte with the given prefix combination.
///
/// # Panics
///
/// Does not panic; returns `None` if no match found.
#[must_use]
pub fn lookup_sse_np(opcode: u8) -> Option<&'static SseInstr> {
    SSE_NP.iter().find(|e| e.opcode == opcode)
}

/// Find an SSE2 66h-prefix instruction by opcode.
#[must_use]
pub fn lookup_sse2_66(opcode: u8) -> Option<&'static SseInstr> {
    SSE2_66.iter().find(|e| e.opcode == opcode)
}

/// Find an SSE F3-prefix instruction by opcode.
#[must_use]
pub fn lookup_sse_f3(opcode: u8) -> Option<&'static SseInstr> {
    SSE_F3.iter().find(|e| e.opcode == opcode)
}

/// Find an SSE F2-prefix instruction by opcode.
#[must_use]
pub fn lookup_sse_f2(opcode: u8) -> Option<&'static SseInstr> {
    SSE_F2.iter().find(|e| e.opcode == opcode)
}

/// Find a SSSE3 instruction by opcode.
#[must_use]
pub fn lookup_ssse3(opcode: u8) -> Option<&'static SseInstr> {
    SSSE3.iter().find(|e| e.opcode == opcode)
}

/// Find an SSE4.1 instruction (0F38) by opcode.
#[must_use]
pub fn lookup_sse41(opcode: u8) -> Option<&'static SseInstr> {
    SSE41.iter().find(|e| e.opcode == opcode)
}

/// Find an SSE4.1 instruction (0F3A) by opcode.
#[must_use]
pub fn lookup_sse41_3a(opcode: u8) -> Option<&'static SseInstr> {
    SSE41_3A.iter().find(|e| e.opcode == opcode)
}

/// Find an SSE4.2 instruction by opcode.
#[must_use]
pub fn lookup_sse42(opcode: u8) -> Option<&'static SseInstr> {
    SSE42.iter().find(|e| e.opcode == opcode)
}

/// Find an SSE-family instruction descriptor by its (lower-case) mnemonic
/// name, searching every table. Used to annotate an already-decoded
/// instruction (e.g. [`crate::x86_simd_decoder::SimdInsn`]) with the richer
/// category/description metadata this module carries, without needing to
/// know which specific opcode-prefix table it lives in.
///
/// When a mnemonic has multiple encodings (e.g. register-form and
/// memory-form, or distinct opcode/prefix variants), the first match is
/// returned; all `SseInstr` variants for a given mnemonic share the same
/// `category` in this table, so any match yields a semantically consistent
/// answer.
#[must_use]
pub fn lookup_by_mnemonic(mnemonic: &str) -> Option<&'static SseInstr> {
    [
        SSE_NP, SSE2_66, SSE_F3, SSE_F2, SSSE3, SSE41, SSE41_3A, SSE42,
    ]
    .iter()
    .find_map(|table| table.iter().find(|e| e.mnemonic == mnemonic))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sse_np_count() {
        assert!(!SSE_NP.is_empty());
    }

    #[test]
    fn test_sse2_66_has_paddb() {
        let e = SSE2_66.iter().find(|i| i.mnemonic == "paddb");
        assert!(e.is_some(), "paddb should be in SSE2_66");
        assert!(e.unwrap().pfx.p66);
    }

    #[test]
    fn test_sse_f3_movss() {
        let e = lookup_sse_f3(0x10);
        assert!(e.is_some());
        assert_eq!(e.unwrap().mnemonic, "movss");
        assert!(e.unwrap().pfx.pf3);
    }

    #[test]
    fn test_sse_f2_movsd() {
        let e = lookup_sse_f2(0x10);
        assert!(e.is_some());
        assert_eq!(e.unwrap().mnemonic, "movsd");
        assert!(e.unwrap().pfx.pf2);
    }

    #[test]
    fn test_ssse3_pshufb() {
        let e = lookup_ssse3(0x00);
        assert!(e.is_some());
        assert_eq!(e.unwrap().mnemonic, "pshufb");
        assert_eq!(e.unwrap().category as u8, SseCategory::Shuffle as u8);
    }

    #[test]
    fn test_sse41_roundps() {
        let e = lookup_sse41_3a(0x08);
        assert!(e.is_some());
        assert_eq!(e.unwrap().mnemonic, "roundps");
    }

    #[test]
    fn test_sse41_pminsb() {
        let e = lookup_sse41(0x38);
        assert!(e.is_some());
        assert_eq!(e.unwrap().mnemonic, "pminsb");
    }

    #[test]
    fn test_sse42_crc32() {
        let e = lookup_sse42(0xF0);
        assert!(e.is_some());
        assert_eq!(e.unwrap().mnemonic, "crc32");
        assert_eq!(e.unwrap().category as u8, SseCategory::Crc as u8);
    }

    #[test]
    fn test_sse42_pcmpgtq() {
        let e = lookup_sse42(0x37);
        assert!(e.is_some());
        assert_eq!(e.unwrap().mnemonic, "pcmpgtq");
    }

    #[test]
    fn test_sse41_aesenc() {
        let e = lookup_sse41(0xDC);
        assert!(e.is_some());
        assert_eq!(e.unwrap().mnemonic, "aesenc");
        assert_eq!(e.unwrap().category as u8, SseCategory::Crypto as u8);
    }

    #[test]
    fn test_lookup_unknown_returns_none() {
        assert!(lookup_sse_np(0xFF).is_none());
    }

    #[test]
    fn test_sse_categories_are_distinct() {
        // Make sure multiple categories are actually used
        let cats: std::collections::HashSet<u8> =
            SSE2_66.iter().map(|i| i.category as u8).collect();
        assert!(cats.len() > 3, "expected multiple SSE categories");
    }

    #[test]
    fn test_sse_f3_addss() {
        let e = lookup_sse_f3(0x58);
        assert!(e.is_some());
        assert_eq!(e.unwrap().mnemonic, "addss");
    }

    #[test]
    fn test_sse_f2_addsd() {
        let e = lookup_sse_f2(0x58);
        assert!(e.is_some());
        assert_eq!(e.unwrap().mnemonic, "addsd");
    }

    #[test]
    fn test_ssse3_pabsb() {
        let e = lookup_ssse3(0x1C);
        assert!(e.is_some());
        assert_eq!(e.unwrap().mnemonic, "pabsb");
    }

    #[test]
    fn test_sse41_3a_pcmpistri() {
        let e = lookup_sse41_3a(0x63);
        assert!(e.is_some());
        assert_eq!(e.unwrap().mnemonic, "pcmpistri");
        assert_eq!(e.unwrap().category as u8, SseCategory::StringText as u8);
    }

    #[test]
    fn test_sse_np_xorps() {
        let e = lookup_sse_np(0x57);
        assert!(e.is_some());
        assert_eq!(e.unwrap().mnemonic, "xorps");
        assert_eq!(e.unwrap().category as u8, SseCategory::Logical as u8);
    }

    #[test]
    fn test_sse2_66_pxor() {
        let e = SSE2_66.iter().find(|i| i.mnemonic == "pxor");
        assert!(e.is_some());
        assert_eq!(e.unwrap().opcode, 0xEF);
    }
}
