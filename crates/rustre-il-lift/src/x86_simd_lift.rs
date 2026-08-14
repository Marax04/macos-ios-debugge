//! x86/x64 SIMD lifting â€” SSE4.2, AVX2, AVX-512 (EVEX), and AMX.
//!
//! # Coverage
//! * **SSE4.2** â€” PCMPESTRI / PCMPESTRM / PCMPISTRI / PCMPISTRM / CRC32 / POPCNT
//! * **AVX2**   â€” VPERMD / VPERMQ / VPGATHERDD / VPGATHERDQ / VPBROADCASTB/W/D/Q
//! * **AVX-512** â€” EVEX prefix handling, opmask-predicated operations,
//!   embedded rounding, VMOVDQU8/16/32/64, VPCMPEQB/W/D/Q
//! * **AMX**    â€” TILELOADD / TILESTORED / TDPBSSD / TILERELEASE / TILEZERO

use super::{ArchLifter, Effect, IrExpr, LiftError, LiftLevel, LiftedInstr};
use rustre_core::arch::Instruction;
use std::fmt;

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// SimdWidth â€” vector register width
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Width of an x86 SIMD register.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SimdWidth {
    /// XMM â€” 128 bits (16 bytes).
    Xmm,
    /// YMM â€” 256 bits (32 bytes).
    Ymm,
    /// ZMM â€” 512 bits (64 bytes).
    Zmm,
}

impl SimdWidth {
    /// Number of bytes in the register.
    #[must_use]
    pub const fn bytes(self) -> usize {
        match self {
            Self::Xmm => 16,
            Self::Ymm => 32,
            Self::Zmm => 64,
        }
    }

    /// Number of 32-bit (DWORD) lanes.
    #[must_use]
    pub const fn dword_lanes(self) -> usize {
        self.bytes() / 4
    }

    /// Number of 64-bit (QWORD) lanes.
    #[must_use]
    pub const fn qword_lanes(self) -> usize {
        self.bytes() / 8
    }
}

impl fmt::Display for SimdWidth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Xmm => write!(f, "xmm"),
            Self::Ymm => write!(f, "ymm"),
            Self::Zmm => write!(f, "zmm"),
        }
    }
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// EvexFlags â€” decoded EVEX prefix fields
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Decoded flags from an EVEX-encoded instruction.
#[derive(Debug, Clone, Default)]
pub struct EvexFlags {
    /// Opmask register k0..k7 (0 = no masking).
    pub opmask: u8,
    /// Zeroing masking (z bit): true â†’ zero masked lanes, false â†’ merge.
    pub zeroing: bool,
    /// Embedded rounding control (er bit). None if not applicable.
    pub rounding: Option<RoundingMode>,
    /// Suppress all exceptions (sae bit).
    pub suppress_exceptions: bool,
    /// Broadcast from memory (b bit applied to mem src).
    pub broadcast: bool,
}

/// Embedded rounding modes available in EVEX static-rounding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoundingMode {
    /// Round to nearest even.
    RoundToNearest,
    /// Round down (toward âˆ’âˆž).
    RoundDown,
    /// Round up (toward +âˆž).
    RoundUp,
    /// Round toward zero (truncate).
    RoundTowardZero,
}

impl fmt::Display for RoundingMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RoundToNearest => write!(f, "rn"),
            Self::RoundDown => write!(f, "rd"),
            Self::RoundUp => write!(f, "ru"),
            Self::RoundTowardZero => write!(f, "rz"),
        }
    }
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// AmxTile â€” AMX tile register
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// An AMX tile register (tmm0..tmm7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AmxTile(pub u8);

impl AmxTile {
    /// Name of the tile register as a string (e.g. `"tmm0"`).
    #[must_use]
    pub fn name(self) -> String {
        format!("tmm{}", self.0)
    }
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// X86SimdLifter
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Lifts x86/x64 SIMD instructions (SSE4.2, AVX2, AVX-512, AMX) to IL effects.
///
/// The lifter models SIMD operations as architecture intrinsics â€” named
/// [`Effect::Intrinsic`] nodes â€” that downstream passes can query or lower.
/// Gather / scatter operations include explicit memory-effect annotations so
/// alias analysis sees them as memory operations.
#[derive(Debug, Clone)]
pub struct X86SimdLifter {
    /// Enable AVX-512 / EVEX instruction decoding.
    pub avx512: bool,
    /// Enable AMX instruction decoding.
    pub amx: bool,
}

impl X86SimdLifter {
    /// Create a lifter that handles all extensions.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            avx512: true,
            amx: true,
        }
    }

    /// Create a lifter for SSE4.2 + AVX2 only (no AVX-512, no AMX).
    #[must_use]
    pub const fn sse42_avx2() -> Self {
        Self {
            avx512: false,
            amx: false,
        }
    }

    // â”€â”€ helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    /// Build an intrinsic effect with the given name and register operands.
    fn intrinsic(name: &str, regs: &[&str]) -> Effect {
        Effect::Intrinsic {
            name: name.to_owned(),
            args: regs.iter().map(|r| IrExpr::Reg(r.to_string())).collect(),
        }
    }

    /// Build an intrinsic with a mix of register and constant arguments.
    fn intrinsic_with_imm(name: &str, regs: &[&str], imm: u64) -> Effect {
        let mut args: Vec<IrExpr> = regs.iter().map(|r| IrExpr::Reg(r.to_string())).collect();
        args.push(IrExpr::Const(imm));
        Effect::Intrinsic {
            name: name.to_owned(),
            args,
        }
    }

    /// Emit an EVEX-predicated write: applies opmask and zeroing semantics.
    ///
    /// When the opmask is 0 the result is written unconditionally (no
    /// masking).  Otherwise a conditional merge/zero is modelled as an
    /// [`Effect::Intrinsic`] named `"evex_merge"` that a later lowering pass
    /// can expand.
    fn evex_write(dest: &str, value: IrExpr, flags: &EvexFlags) -> Vec<Effect> {
        if flags.opmask == 0 {
            return vec![Effect::RegWrite {
                reg: dest.to_owned(),
                value,
            }];
        }
        let mask_reg = format!("k{}", flags.opmask);
        let zero_flag = u64::from(flags.zeroing);
        vec![Effect::Intrinsic {
            name: "evex_merge".to_owned(),
            args: vec![
                IrExpr::Reg(dest.to_owned()),
                value,
                IrExpr::Reg(mask_reg),
                IrExpr::Const(zero_flag),
            ],
        }]
    }

    // â”€â”€ SSE4.2 â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    fn lift_sse42(mnem: &str, ops: &str) -> Option<Vec<Effect>> {
        let parts: Vec<&str> = ops.split_whitespace().collect();
        match mnem {
            // PCMPESTRI xmm1, xmm2/m128, imm8
            // Compare packed byte/word strings with explicit lengths.
            // ECX â† index of least/most significant match bit.
            "pcmpestri" => {
                let xmm1 = parts.first().copied().unwrap_or("xmm0");
                let xmm2 = parts.get(1).copied().unwrap_or("xmm1");
                let imm = parse_imm(parts.get(2).copied().unwrap_or("0"));
                Some(vec![
                    Self::intrinsic_with_imm("sse42_pcmpestri", &[xmm1, xmm2], imm),
                    // ECX receives the result index; ZF/CF set by comparison.
                    Effect::RegWrite {
                        reg: "ecx".to_owned(),
                        value: IrExpr::Reg(format!("__pcmpestri_idx_{imm}")),
                    },
                ])
            }
            // PCMPESTRM xmm1, xmm2/m128, imm8
            // Compare packed strings; result mask written to XMM0.
            "pcmpestrm" => {
                let xmm1 = parts.first().copied().unwrap_or("xmm0");
                let xmm2 = parts.get(1).copied().unwrap_or("xmm1");
                let imm = parse_imm(parts.get(2).copied().unwrap_or("0"));
                Some(vec![
                    Self::intrinsic_with_imm("sse42_pcmpestrm", &[xmm1, xmm2], imm),
                    Effect::RegWrite {
                        reg: "xmm0".to_owned(),
                        value: IrExpr::Reg(format!("__pcmpestrm_mask_{imm}")),
                    },
                ])
            }
            // PCMPISTRI xmm1, xmm2/m128, imm8 â€” implicit-length string compare.
            "pcmpistri" => {
                let xmm1 = parts.first().copied().unwrap_or("xmm0");
                let xmm2 = parts.get(1).copied().unwrap_or("xmm1");
                let imm = parse_imm(parts.get(2).copied().unwrap_or("0"));
                Some(vec![
                    Self::intrinsic_with_imm("sse42_pcmpistri", &[xmm1, xmm2], imm),
                    Effect::RegWrite {
                        reg: "ecx".to_owned(),
                        value: IrExpr::Reg(format!("__pcmpistri_idx_{imm}")),
                    },
                ])
            }
            // PCMPISTRM xmm1, xmm2/m128, imm8 â€” result mask in XMM0.
            "pcmpistrm" => {
                let xmm1 = parts.first().copied().unwrap_or("xmm0");
                let xmm2 = parts.get(1).copied().unwrap_or("xmm1");
                let imm = parse_imm(parts.get(2).copied().unwrap_or("0"));
                Some(vec![
                    Self::intrinsic_with_imm("sse42_pcmpistrm", &[xmm1, xmm2], imm),
                    Effect::RegWrite {
                        reg: "xmm0".to_owned(),
                        value: IrExpr::Reg(format!("__pcmpistrm_mask_{imm}")),
                    },
                ])
            }
            // CRC32 r32/r64, r/m8/16/32/64
            // Accumulate CRC-32C into destination register.
            "crc32" => {
                let dst = parts.first().copied().unwrap_or("eax");
                let src = parts.get(1).copied().unwrap_or("ecx");
                Some(vec![Effect::RegWrite {
                    reg: dst.to_owned(),
                    value: IrExpr::Reg(format!("__crc32({dst},{src})")),
                }])
            }
            // POPCNT r, r/m â€” population count (number of 1 bits).
            "popcnt" => {
                let dst = parts.first().copied().unwrap_or("eax");
                let src = parts.get(1).copied().unwrap_or("ecx");
                Some(vec![Effect::RegWrite {
                    reg: dst.to_owned(),
                    value: IrExpr::Reg(format!("__popcnt({src})")),
                }])
            }
            _ => None,
        }
    }

    // â”€â”€ AVX2 â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    fn lift_avx2(mnem: &str, ops: &str) -> Option<Vec<Effect>> {
        let parts: Vec<&str> = ops.split_whitespace().collect();
        match mnem {
            // VPERMD ymm1, ymm2, ymm3/m256
            // Permute 32-bit elements of ymm3 using indices from ymm2.
            "vpermd" => {
                let dst = parts.first().copied().unwrap_or("ymm0");
                let idx = parts.get(1).copied().unwrap_or("ymm1");
                let src = parts.get(2).copied().unwrap_or("ymm2");
                Some(vec![Effect::RegWrite {
                    reg: dst.to_owned(),
                    value: IrExpr::Reg(format!("__vpermd({src},{idx})")),
                }])
            }
            // VPERMQ ymm1, ymm2/m256, imm8
            // Permute 64-bit elements using 4-bit index from imm8.
            "vpermq" => {
                let dst = parts.first().copied().unwrap_or("ymm0");
                let src = parts.get(1).copied().unwrap_or("ymm1");
                let imm = parse_imm(parts.get(2).copied().unwrap_or("0"));
                Some(vec![Effect::RegWrite {
                    reg: dst.to_owned(),
                    value: IrExpr::Reg(format!("__vpermq({src},{imm})")),
                }])
            }
            // VPGATHERDD ymm1, [base+ymm2*scale+disp], ymm3
            // Gather DWORD values from memory using 32-bit indices.
            "vpgatherdd" => {
                let dst = parts.first().copied().unwrap_or("ymm0");
                let mask = parts.get(2).copied().unwrap_or("ymm1");
                // Model as a memory-read intrinsic; address is symbolic.
                Some(vec![
                    Effect::Intrinsic {
                        name: "avx2_vpgatherdd".to_owned(),
                        args: vec![
                            IrExpr::Reg(dst.to_owned()),
                            IrExpr::Reg("mem_base".to_owned()),
                            IrExpr::Reg(mask.to_owned()),
                        ],
                    },
                    Effect::RegWrite {
                        reg: dst.to_owned(),
                        value: IrExpr::Reg("__vpgatherdd_result".to_string()),
                    },
                ])
            }
            // VPGATHERDQ ymm1, [base+xmm2*scale+disp], ymm3
            // Gather QWORD values using 32-bit indices in xmm2.
            "vpgatherdq" => {
                let dst = parts.first().copied().unwrap_or("ymm0");
                let mask = parts.get(2).copied().unwrap_or("ymm1");
                Some(vec![
                    Effect::Intrinsic {
                        name: "avx2_vpgatherdq".to_owned(),
                        args: vec![
                            IrExpr::Reg(dst.to_owned()),
                            IrExpr::Reg("mem_base".to_owned()),
                            IrExpr::Reg(mask.to_owned()),
                        ],
                    },
                    Effect::RegWrite {
                        reg: dst.to_owned(),
                        value: IrExpr::Reg("__vpgatherdq_result".to_owned()),
                    },
                ])
            }
            // VPBROADCASTB/W/D/Q â€” broadcast element to all lanes.
            "vpbroadcastb" | "vpbroadcastw" | "vpbroadcastd" | "vpbroadcastq" => {
                let dst = parts.first().copied().unwrap_or("ymm0");
                let src = parts.get(1).copied().unwrap_or("xmm0");
                let elem_sz = match mnem {
                    "vpbroadcastb" => 1u64,
                    "vpbroadcastw" => 2,
                    "vpbroadcastd" => 4,
                    _ => 8,
                };
                Some(vec![Effect::RegWrite {
                    reg: dst.to_owned(),
                    value: IrExpr::Reg(format!("__vpbroadcast_{elem_sz}({src})")),
                }])
            }
            _ => None,
        }
    }

    // â”€â”€ AVX-512 â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    fn lift_avx512(&self, mnem: &str, ops: &str, evex: &EvexFlags) -> Option<Vec<Effect>> {
        let parts: Vec<&str> = ops.split_whitespace().collect();
        // Strip opmask suffix from destination (e.g. "zmm1{k1}{z}" â†’ "zmm1").
        let raw_dst = parts.first().copied().unwrap_or("zmm0");
        let dst = strip_opmask_suffix(raw_dst);

        match mnem {
            // VMOVDQU8/16/32/64 â€” move unaligned packed integers.
            "vmovdqu8" | "vmovdqu16" | "vmovdqu32" | "vmovdqu64" => {
                let src = parts.get(1).copied().unwrap_or("zmm1");
                let src = strip_opmask_suffix(src);
                let mut effs = Self::evex_write(
                    dst,
                    IrExpr::Reg(src.to_owned()),
                    evex,
                );
                effs.push(Effect::Intrinsic {
                    name: format!("avx512_{mnem}"),
                    args: vec![IrExpr::Reg(dst.to_owned()), IrExpr::Reg(src.to_owned())],
                });
                Some(effs)
            }
            // VPCMPEQB/W/D/Q â€” compare packed integers, result to opmask.
            "vpcmpeqb" | "vpcmpeqw" | "vpcmpeqd" | "vpcmpeqq" => {
                let src1 = parts.get(1).copied().unwrap_or("zmm1");
                let src2 = parts.get(2).copied().unwrap_or("zmm2");
                // Result is a mask register (k register) when EVEX-encoded.
                let is_mask_dst = dst.starts_with('k');
                if is_mask_dst {
                    Some(vec![Effect::RegWrite {
                        reg: dst.to_owned(),
                        value: IrExpr::Reg(format!("__vpcmpeq({src1},{src2})")),
                    }])
                } else {
                    let mut effs = Self::evex_write(
                        dst,
                        IrExpr::Reg(format!("__vpcmpeq({src1},{src2})")),
                        evex,
                    );
                    effs.push(Self::intrinsic(
                        &format!("avx512_{mnem}"),
                        &[dst, src1, src2],
                    ));
                    Some(effs)
                }
            }
            // VPTERNLOGD/Q zmm1 {k1}{z}, zmm2, zmm3/m512/m32bcst, imm8
            // Ternary bitwise logic on 32/64-bit elements.
            "vpternlogd" | "vpternlogq" => {
                let src2 = parts.get(1).copied().unwrap_or("zmm1");
                let src3 = parts.get(2).copied().unwrap_or("zmm2");
                let imm = parse_imm(parts.get(3).copied().unwrap_or("0"));
                let val = IrExpr::Reg(format!("__vpternlog({dst},{src2},{src3},{imm})"));
                Some(Self::evex_write(dst, val, evex))
            }
            // VRANGEPS/D â€” compute range (min/max/abs-based) with embedded rounding.
            "vrangeps" | "vrangepd" => {
                let src1 = parts.get(1).copied().unwrap_or("zmm1");
                let src2 = parts.get(2).copied().unwrap_or("zmm2");
                let imm = parse_imm(parts.get(3).copied().unwrap_or("0"));
                let rnd_note = evex
                    .rounding
                    .map(|r| format!(",{r}"))
                    .unwrap_or_default();
                let val = IrExpr::Reg(format!("__vrange({src1},{src2},{imm}{rnd_note})"));
                Some(Self::evex_write(dst, val, evex))
            }
            // Generic AVX-512 fall-through: model as intrinsic.
            _ if mnem.starts_with('v') && self.avx512 => {
                let args: Vec<IrExpr> = parts
                    .iter()
                    .map(|&s| IrExpr::Reg(strip_opmask_suffix(s).to_owned()))
                    .collect();
                Some(vec![Effect::Intrinsic {
                    name: format!("avx512_{mnem}"),
                    args,
                }])
            }
            _ => None,
        }
    }

    // â”€â”€ AMX â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    fn lift_amx(mnem: &str, ops: &str) -> Option<Vec<Effect>> {
        let parts: Vec<&str> = ops.split_whitespace().collect();
        match mnem {
            // TILELOADD tmm1, [base+stride]
            // Load tile from memory using row-stride descriptor.
            "tileloadd" | "tileloaddt1" => {
                let tile = parts.first().copied().unwrap_or("tmm0");
                let base = parts.get(1).copied().unwrap_or("rsi");
                let stride = parts.get(2).copied().unwrap_or("rdx");
                Some(vec![
                    Effect::MemRead {
                        addr: IrExpr::Reg(base.to_owned()),
                        dest: tile.to_owned(),
                        size: 64, // up to 1 KiB per tile; use 64 as symbolic unit
                    },
                    Effect::Intrinsic {
                        name: "amx_tileloadd".to_owned(),
                        args: vec![
                            IrExpr::Reg(tile.to_owned()),
                            IrExpr::Reg(base.to_owned()),
                            IrExpr::Reg(stride.to_owned()),
                        ],
                    },
                ])
            }
            // TILESTORED [base+stride], tmm1
            "tilestored" => {
                let base = parts.first().copied().unwrap_or("rdi");
                let stride = parts.get(1).copied().unwrap_or("rdx");
                let tile = parts.get(2).copied().unwrap_or("tmm0");
                Some(vec![
                    Effect::MemWrite {
                        addr: IrExpr::Reg(base.to_owned()),
                        value: IrExpr::Reg(tile.to_owned()),
                        size: 64,
                    },
                    Effect::Intrinsic {
                        name: "amx_tilestored".to_owned(),
                        args: vec![
                            IrExpr::Reg(base.to_owned()),
                            IrExpr::Reg(stride.to_owned()),
                            IrExpr::Reg(tile.to_owned()),
                        ],
                    },
                ])
            }
            // TDPBSSD tmm1, tmm2, tmm3
            // Dot product of signed bytes: tmm1 += tmm2 * tmm3 (int8 Ã— int8 â†’ int32).
            "tdpbssd" => {
                let acc = parts.first().copied().unwrap_or("tmm0");
                let a = parts.get(1).copied().unwrap_or("tmm1");
                let b = parts.get(2).copied().unwrap_or("tmm2");
                Some(vec![Effect::RegWrite {
                    reg: acc.to_owned(),
                    value: IrExpr::Add(
                        Box::new(IrExpr::Reg(acc.to_owned())),
                        Box::new(IrExpr::Reg(format!("__dot_i8({a},{b})"))),
                    ),
                }])
            }
            // TDPBF16PS tmm1, tmm2, tmm3 â€” BF16 dot product accumulate into FP32.
            "tdpbf16ps" => {
                let acc = parts.first().copied().unwrap_or("tmm0");
                let a = parts.get(1).copied().unwrap_or("tmm1");
                let b = parts.get(2).copied().unwrap_or("tmm2");
                Some(vec![Effect::RegWrite {
                    reg: acc.to_owned(),
                    value: IrExpr::Add(
                        Box::new(IrExpr::Reg(acc.to_owned())),
                        Box::new(IrExpr::Reg(format!("__dot_bf16({a},{b})"))),
                    ),
                }])
            }
            // TILEZERO tmm1 â€” zero all bytes of a tile register.
            "tilezero" => {
                let tile = parts.first().copied().unwrap_or("tmm0");
                Some(vec![Effect::RegWrite {
                    reg: tile.to_owned(),
                    value: IrExpr::Const(0),
                }])
            }
            // TILERELEASE â€” release all tile registers (no explicit operands).
            "tilerelease" => Some(vec![Effect::Intrinsic {
                name: "amx_tilerelease".to_owned(),
                args: vec![],
            }]),
            // LDTILECFG / STTILECFG m512 â€” configure tile sizes.
            "ldtilecfg" => {
                let src = parts.first().copied().unwrap_or("mem");
                Some(vec![Effect::Intrinsic {
                    name: "amx_ldtilecfg".to_owned(),
                    args: vec![IrExpr::Reg(src.to_owned())],
                }])
            }
            "sttilecfg" => {
                let dst = parts.first().copied().unwrap_or("mem");
                Some(vec![Effect::Intrinsic {
                    name: "amx_sttilecfg".to_owned(),
                    args: vec![IrExpr::Reg(dst.to_owned())],
                }])
            }
            _ => None,
        }
    }
}

impl Default for X86SimdLifter {
    fn default() -> Self {
        Self::new()
    }
}

impl ArchLifter for X86SimdLifter {
    fn arch_name(&self) -> &'static str {
        "x86_simd"
    }

    fn lift_level(&self) -> LiftLevel {
        LiftLevel::Llil
    }

    fn description(&self) -> &'static str {
        "x86/x64 SIMD lifter â€” SSE4.2, AVX2, AVX-512, AMX"
    }

    fn lift(&self, instr: &Instruction) -> Result<LiftedInstr, LiftError> {
        let mnem = instr.mnemonic.to_lowercase();
        let ops = instr.operands.as_str();

        // Detect EVEX encoding from mnemonic prefix or operand suffixes.
        let evex = EvexFlags {
            opmask: extract_opmask(ops),
            zeroing: ops.contains("{z}"),
            rounding: extract_rounding(ops),
            suppress_exceptions: ops.contains("{sae}"),
            broadcast: ops.contains("{1to"),
        };

        let effects = Self::lift_sse42(&mnem, ops)
            .or_else(|| Self::lift_avx2(&mnem, ops))
            .or_else(|| {
                if self.avx512 {
                    self.lift_avx512(&mnem, ops, &evex)
                } else {
                    None
                }
            })
            .or_else(|| {
                if self.amx {
                    Self::lift_amx(&mnem, ops)
                } else {
                    None
                }
            })
            .ok_or_else(|| {
                LiftError::LiftFailed(
                    instr.address.into(),
                    format!("x86_simd: unhandled mnemonic '{mnem}'"),
                )
            })?;

        let ir_text = effects.iter().map(std::string::ToString::to_string).collect::<Vec<_>>().join("; ");
        Ok(LiftedInstr {
            address: instr.address.0,
            original_mnemonic: instr.mnemonic.clone(),
            ir_text,
            il_level: LiftLevel::Llil,
            effects,
        })
    }
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// Free helpers
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Parse an immediate operand string like `"0x3f"` or `"63"` to `u64`.
fn parse_imm(s: &str) -> u64 {
    let s = s.trim_matches(',').trim();
    s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).map_or_else(|| s.parse().unwrap_or(0), |hex| u64::from_str_radix(hex, 16).unwrap_or(0))
}

/// Strip opmask suffixes such as `"{k1}"` or `"{k2}{z}"` from a token.
fn strip_opmask_suffix(s: &str) -> &str {
    s.find('{').map_or(s, |idx| &s[..idx])
}

/// Extract the first opmask register number from an operand string.
fn extract_opmask(ops: &str) -> u8 {
    if let Some(idx) = ops.find("{k") {
        let rest = &ops[idx + 2..];
        if let Some(end_idx) = rest.find('}')
            && let Ok(n) = rest[..end_idx].parse::<u8>()
                && n <= 7 {
                    return n;
                }
    }
    0
}

/// Extract embedded rounding mode from operand string.
fn extract_rounding(ops: &str) -> Option<RoundingMode> {
    if ops.contains("{rn-sae}") || ops.contains("{rn}") {
        Some(RoundingMode::RoundToNearest)
    } else if ops.contains("{rd-sae}") || ops.contains("{rd}") {
        Some(RoundingMode::RoundDown)
    } else if ops.contains("{ru-sae}") || ops.contains("{ru}") {
        Some(RoundingMode::RoundUp)
    } else if ops.contains("{rz-sae}") || ops.contains("{rz}") {
        Some(RoundingMode::RoundTowardZero)
    } else {
        None
    }
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// Tests
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

#[cfg(test)]
mod tests {
    use super::*;

    fn make_instr(mnem: &str, ops: &str) -> Instruction {
        let mut i = Instruction::new(
            rustre_core::address::Address::new(0x1000),
            4,
            mnem,
            vec![],
        );
        i.operands = ops.to_owned();
        i
    }

    #[test]
    fn test_popcnt() {
        let lifter = X86SimdLifter::new();
        let instr = make_instr("popcnt", "eax ecx");
        let result = lifter.lift(&instr).unwrap();
        assert!(!result.effects.is_empty());
        match &result.effects[0] {
            Effect::RegWrite { reg, .. } => assert_eq!(reg, "eax"),
            _ => panic!("expected RegWrite"),
        }
    }

    #[test]
    fn test_crc32() {
        let lifter = X86SimdLifter::new();
        let instr = make_instr("crc32", "eax ecx");
        let result = lifter.lift(&instr).unwrap();
        assert!(!result.effects.is_empty());
    }

    #[test]
    fn test_tilezero() {
        let lifter = X86SimdLifter::new();
        let instr = make_instr("tilezero", "tmm0");
        let result = lifter.lift(&instr).unwrap();
        assert!(matches!(
            &result.effects[0],
            Effect::RegWrite { reg, value: IrExpr::Const(0) } if reg == "tmm0"
        ));
    }

    #[test]
    fn test_vpbroadcastd() {
        let lifter = X86SimdLifter::new();
        let instr = make_instr("vpbroadcastd", "ymm1 xmm2");
        let result = lifter.lift(&instr).unwrap();
        assert!(!result.effects.is_empty());
    }

    #[test]
    fn test_evex_opmask_extraction() {
        assert_eq!(extract_opmask("zmm1{k3}{z} zmm2 zmm3"), 3);
        assert_eq!(extract_opmask("zmm0 zmm1"), 0);
    }

    #[test]
    fn test_parse_imm() {
        assert_eq!(parse_imm("0x3f"), 63);
        assert_eq!(parse_imm("42"), 42);
        assert_eq!(parse_imm("0XFF"), 255);
    }
}
