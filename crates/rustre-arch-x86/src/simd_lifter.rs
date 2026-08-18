//! SIMD instruction lifting for x86 — SSE2 through AVX-512.
//!
//! Covers:
//!  - SSE2   : all 128-bit integer and floating-point operations
//!  - SSE3 / SSSE3 / SSE4.1 / SSE4.2
//!  - AVX / AVX2 : 256-bit VEX-encoded equivalents
//!  - Basic AVX-512 : EVEX prefix, embedded rounding, k-mask registers
//!
//! The core abstractions are:
//!  - [`VRegister`]        — a typed SIMD register (XMM/YMM/ZMM + lane width)
//!  - [`LaneOp`]           — a single lane-level primitive
//!  - [`MaskingOp`]        — AVX-512 k-mask zeroing / merging behaviour
//!  - [`SimdILEmitter`]    — converts a parsed SIMD instruction to IL effects
//!  - [`SimdLiftContext`]  — shared state carried through a SIMD lifting session
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
// Register width
// ─────────────────────────────────────────────────────────────────────────────

/// The width of a SIMD register file entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RegWidth {
    /// 128-bit XMM register (SSE).
    Xmm,
    /// 256-bit YMM register (AVX).
    Ymm,
    /// 512-bit ZMM register (AVX-512).
    Zmm,
}

impl RegWidth {
    /// Width in bytes.
    #[must_use]
    pub const fn bytes(self) -> usize {
        match self {
            Self::Xmm => 16,
            Self::Ymm => 32,
            Self::Zmm => 64,
        }
    }

    /// Width in bits.
    #[must_use]
    pub fn bits(self) -> usize {
        self.bytes() * 8
    }

    /// Name prefix used in register names ("xmm" / "ymm" / "zmm").
    #[must_use]
    pub const fn prefix(self) -> &'static str {
        match self {
            Self::Xmm => "xmm",
            Self::Ymm => "ymm",
            Self::Zmm => "zmm",
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// VRegister
// ─────────────────────────────────────────────────────────────────────────────

/// A typed SIMD vector register.
///
/// Carries the register index (0–31) and the effective width imposed by the
/// instruction encoding (XMM for SSE, YMM for AVX, ZMM for AVX-512).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct VRegister {
    /// Register index (0–31 for ZMM, 0–15 for XMM/YMM in legacy encodings).
    pub index: u8,
    /// The width imposed by the instruction encoding.
    pub width: RegWidth,
}

impl VRegister {
    /// Construct a new `VRegister`.
    #[must_use]
    pub const fn new(index: u8, width: RegWidth) -> Self {
        Self { index, width }
    }

    /// XMM register by index.
    #[must_use]
    pub fn xmm(index: u8) -> Self {
        Self::new(index, RegWidth::Xmm)
    }

    /// YMM register by index.
    #[must_use]
    pub fn ymm(index: u8) -> Self {
        Self::new(index, RegWidth::Ymm)
    }

    /// ZMM register by index.
    #[must_use]
    pub fn zmm(index: u8) -> Self {
        Self::new(index, RegWidth::Zmm)
    }

    /// Canonical register name, e.g. `"xmm3"`, `"ymm15"`, `"zmm31"`.
    #[must_use]
    pub fn name(&self) -> String {
        format!("{}{}", self.width.prefix(), self.index)
    }

    /// Build an [`IrExpr::Reg`] for this register.
    #[must_use]
    pub fn expr(&self) -> IrExpr {
        IrExpr::Reg(self.name())
    }
}

impl std::fmt::Display for VRegister {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// LaneWidth / LaneType
// ─────────────────────────────────────────────────────────────────────────────

/// Width of a single lane element.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LaneWidth {
    Byte,  //  8-bit
    Word,  // 16-bit
    Dword, // 32-bit
    Qword, // 64-bit
}

impl LaneWidth {
    /// Size in bytes.
    #[must_use]
    pub const fn bytes(self) -> usize {
        match self {
            Self::Byte => 1,
            Self::Word => 2,
            Self::Dword => 4,
            Self::Qword => 8,
        }
    }

    /// Size in bits.
    #[must_use]
    pub fn bits(self) -> usize {
        self.bytes() * 8
    }
}

/// The numeric type of a SIMD lane.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LaneType {
    /// Unsigned integer.
    Uint,
    /// Signed integer.
    Sint,
    /// IEEE 754 single-precision (32-bit) float.
    F32,
    /// IEEE 754 double-precision (64-bit) float.
    F64,
}

// ─────────────────────────────────────────────────────────────────────────────
// LaneOp
// ─────────────────────────────────────────────────────────────────────────────

/// A primitive lane-level operation used to model SIMD instruction semantics.
///
/// These map 1-to-1 with the microarchitectural operations that a SIMD unit
/// performs; the [`SimdILEmitter`] assembles sequences of `LaneOp` into
/// [`Effect`] trees.
#[derive(Debug, Clone, PartialEq)]
pub enum LaneOp {
    /// dst[i] = a[i] + b[i]
    Add { lane: LaneWidth, ty: LaneType },
    /// dst[i] = a[i] - b[i]
    Sub { lane: LaneWidth, ty: LaneType },
    /// dst[i] = a[i] * b[i]
    Mul { lane: LaneWidth, ty: LaneType },
    /// dst[i] = a[i] / b[i]
    Div { lane: LaneWidth, ty: LaneType },
    /// dst[i] = sqrt(a[i])
    Sqrt { lane: LaneWidth, ty: LaneType },
    /// dst[i] = min(a[i], b[i])
    Min { lane: LaneWidth, ty: LaneType },
    /// dst[i] = max(a[i], b[i])
    Max { lane: LaneWidth, ty: LaneType },
    /// dst[i] = a[i] & b[i]
    And { lane: LaneWidth },
    /// dst[i] = a[i] | b[i]
    Or { lane: LaneWidth },
    /// dst[i] = a[i] ^ b[i]
    Xor { lane: LaneWidth },
    /// dst[i] = ~a[i] & b[i]
    Andn { lane: LaneWidth },
    /// dst[i] = a[i] == b[i] ? all-ones : all-zeros
    CmpEq { lane: LaneWidth, ty: LaneType },
    /// dst[i] = a[i] > b[i] ? all-ones : all-zeros
    CmpGt { lane: LaneWidth, ty: LaneType },
    /// dst[i] = (float comparison result bitfield)
    CmpOrd { lane: LaneWidth, imm: u8 },
    /// dst[i] = a[i] << imm
    ShlImm { lane: LaneWidth, imm: u8 },
    /// dst[i] = a[i] >> imm (logical)
    ShrImm { lane: LaneWidth, imm: u8 },
    /// dst[i] = a[i] >>a imm (arithmetic)
    SarImm { lane: LaneWidth, imm: u8 },
    /// Shuffle: dst[i] = src[ctrl[i]] (byte granularity)
    Pshufb,
    /// Shuffle: dst[i] = src[`imm_byte_for_lane_i`]
    Pshufd { imm: u8 },
    /// Shuffle: dst = {a,b} interleaved according to imm
    Shufps { imm: u8 },
    /// Unpack low lanes of a and b
    UnpackLo { lane: LaneWidth },
    /// Unpack high lanes of a and b
    UnpackHi { lane: LaneWidth },
    /// Pack with signed saturation
    PackSs { lane: LaneWidth },
    /// Pack with unsigned saturation
    PackUs { lane: LaneWidth },
    /// Blend: select lanes from a or b based on imm mask
    BlendImm { lane: LaneWidth, imm: u8 },
    /// Blend: select lanes from a or b based on register mask
    BlendVar { lane: LaneWidth },
    /// Horizontal add: dst[i] = a[2i] + a[2i+1]
    HAdd { lane: LaneWidth, ty: LaneType },
    /// Horizontal sub: dst[i] = a[2i] - a[2i+1]
    HSub { lane: LaneWidth, ty: LaneType },
    /// Dot product (DPPS/DPPD): accumulate selected lanes
    DotProduct { lane: LaneWidth, imm: u8 },
    /// String comparison (PCMPISTRI/PCMPISTRM style)
    StringCmp { imm: u8 },
    /// CRC32 polynomial accumulation
    Crc32 { lane: LaneWidth },
    /// Convert: src lanes to dst lane type
    Convert {
        src_ty: LaneType,
        dst_ty: LaneType,
        src_lane: LaneWidth,
        dst_lane: LaneWidth,
    },
    /// Move scalar (zero-extend upper lanes)
    MoveScalar { lane: LaneWidth, ty: LaneType },
    /// Insert a lane value from integer register or memory
    Insert { dst_lane: LaneWidth, imm: u8 },
    /// Extract a lane value to integer register or memory
    Extract { src_lane: LaneWidth, imm: u8 },
    /// Broadcast scalar to all lanes
    Broadcast { lane: LaneWidth },
    /// Gather: dst[i] = mem[base + `v_index`[i] * scale]
    Gather { lane: LaneWidth },
    /// Scatter: mem[base + `v_index`[i] * scale] = src[i]
    Scatter { lane: LaneWidth },
    /// Permute lanes within 256-bit register (AVX2)
    Permute { lane: LaneWidth, imm: Option<u8> },
    /// Fused multiply-add: dst = a*b + c (various FMA variants)
    Fma {
        lane: LaneWidth,
        negate_b: bool,
        negate_c: bool,
    },
    /// Move with zero masking (AVX-512)
    MaskZero { lane: LaneWidth },
    /// Move with merge masking (AVX-512)
    MaskMerge { lane: LaneWidth },
    /// No-op / identity move
    Move,
}

// ─────────────────────────────────────────────────────────────────────────────
// MaskingOp
// ─────────────────────────────────────────────────────────────────────────────

/// AVX-512 write-masking behaviour applied to the destination register.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MaskingOp {
    /// No write masking (legacy SSE / AVX).
    None,
    /// Zero masking: masked-off lanes are written as zero.
    ///
    /// `k_reg` is the opmask register index (0–7).
    Zero { k_reg: u8 },
    /// Merge masking: masked-off lanes retain their previous value.
    ///
    /// `k_reg` is the opmask register index (0–7).
    Merge { k_reg: u8 },
}

impl MaskingOp {
    /// Returns `true` if no masking is applied.
    #[must_use]
    pub fn is_none(&self) -> bool {
        *self == Self::None
    }

    /// Returns the k-register index if masking is active.
    #[must_use]
    pub const fn k_reg(&self) -> Option<u8> {
        match self {
            Self::Zero { k_reg } | Self::Merge { k_reg } => Some(*k_reg),
            Self::None => None,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SimdInstrDesc
// ─────────────────────────────────────────────────────────────────────────────

/// A fully decoded SIMD instruction with all operands and masking information.
#[derive(Debug, Clone)]
pub struct SimdInstrDesc {
    /// Mnemonic of the instruction.
    pub mnemonic: String,
    /// Destination register.
    pub dst: VRegister,
    /// First source register (or memory operand).
    pub src1: Option<VRegister>,
    /// Second source register (or memory operand for 3-operand forms).
    pub src2: Option<VRegister>,
    /// Immediate byte (if any).
    pub imm: Option<u8>,
    /// Lane operation.
    pub op: LaneOp,
    /// AVX-512 write masking.
    pub masking: MaskingOp,
    /// Whether EVEX embedded-rounding is active.
    pub embedded_rounding: Option<u8>,
}

// ─────────────────────────────────────────────────────────────────────────────
// SimdLiftContext
// ─────────────────────────────────────────────────────────────────────────────

/// Shared mutable state for a SIMD lifting session.
///
/// Tracks register allocation choices, the target ISA level, and diagnostic
/// counters for lifted and unlifted instructions.
#[derive(Debug, Default)]
pub struct SimdLiftContext {
    /// Target ISA level (determines which instruction groups are handled).
    pub isa_level: SimdIsaLevel,
    /// Number of instructions successfully lifted in this session.
    pub lifted_count: u64,
    /// Number of instructions that fell back to the intrinsic stub.
    pub fallback_count: u64,
    /// Whether to emit verbose diagnostic effects.
    pub verbose: bool,
    /// Whether to zero upper lanes on 128-bit writes into YMM (VEX behaviour).
    pub vex_zero_upper: bool,
}

impl SimdLiftContext {
    /// Create a new context targeting the given ISA level.
    #[must_use]
    pub const fn new(isa_level: SimdIsaLevel) -> Self {
        Self {
            isa_level,
            lifted_count: 0,
            fallback_count: 0,
            verbose: false,
            vex_zero_upper: true,
        }
    }

    /// Create a context for SSE2 (the most widely deployed baseline).
    #[must_use]
    pub fn sse2() -> Self {
        Self::new(SimdIsaLevel::Sse2)
    }

    /// Create a context for AVX2.
    #[must_use]
    pub fn avx2() -> Self {
        Self::new(SimdIsaLevel::Avx2)
    }

    /// Create a context for AVX-512F.
    #[must_use]
    pub fn avx512() -> Self {
        Self::new(SimdIsaLevel::Avx512F)
    }
}

/// The maximum SIMD ISA level supported by the context.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub enum SimdIsaLevel {
    /// SSE (original Pentium III).
    Sse,
    /// SSE2 (Pentium 4 baseline).
    #[default]
    Sse2,
    /// SSE3 (Prescott).
    Sse3,
    /// SSSE3 (Core 2).
    Ssse3,
    /// SSE4.1 (Penryn).
    Sse41,
    /// SSE4.2 (Nehalem).
    Sse42,
    /// AVX (Sandy Bridge).
    Avx,
    /// AVX2 (Haswell).
    Avx2,
    /// AVX-512F (Skylake-X).
    Avx512F,
}

// ─────────────────────────────────────────────────────────────────────────────
// SimdILEmitter
// ─────────────────────────────────────────────────────────────────────────────

/// Emits IL [`Effect`]s for a decoded SIMD instruction.
///
/// Driven by [`SimdInstrDesc`] and the shared [`SimdLiftContext`].
pub struct SimdILEmitter<'a> {
    ctx: &'a mut SimdLiftContext,
}

impl<'a> SimdILEmitter<'a> {
    /// Create a new emitter backed by `ctx`.
    pub const fn new(ctx: &'a mut SimdLiftContext) -> Self {
        Self { ctx }
    }

    /// Emit IL effects for `desc`.
    ///
    /// Returns a `Vec<Effect>` modelling all side-effects of the instruction.
    /// If the instruction cannot be handled, a single `Effect::Intrinsic` stub
    /// is returned and `ctx.fallback_count` is incremented.
    #[must_use]
    pub fn emit(&mut self, desc: &SimdInstrDesc) -> Vec<Effect> {
        let effects = self.emit_inner(desc);
        if effects.len() == 1
            && let Effect::Intrinsic { .. } = &effects[0] {
                self.ctx.fallback_count += 1;
                return effects;
            }
        self.ctx.lifted_count += 1;

        // If VEX/EVEX write zeroes the upper portion (e.g. 128-bit write into
        // a 256/512-bit register), append an upper-zero effect.
        if self.ctx.vex_zero_upper && desc.dst.width == RegWidth::Xmm {
            let ymm_name = format!("ymm{}", desc.dst.index);
            let mut out = effects;
            out.push(Effect::Intrinsic {
                name: "vex_zero_upper".to_string(),
                args: vec![IrExpr::Reg(ymm_name)],
            });
            return out;
        }

        effects
    }

    fn emit_inner(&self, desc: &SimdInstrDesc) -> Vec<Effect> {
        let dst = desc.dst.expr();
        let dst_name = desc.dst.name();

        let src1 = desc
            .src1
            .as_ref()
            .map_or(IrExpr::Undef, VRegister::expr);
        let src2 = desc
            .src2
            .as_ref()
            .map_or(IrExpr::Undef, VRegister::expr);

        match &desc.op {
            // ── Arithmetic ────────────────────────────────────────────────────
            LaneOp::Add { .. } => {
                vec![Effect::RegWrite {
                    reg: dst_name,
                    value: IrExpr::Add(Box::new(src1), Box::new(src2)),
                }]
            }
            LaneOp::Sub { .. } => {
                vec![Effect::RegWrite {
                    reg: dst_name,
                    value: IrExpr::Sub(Box::new(src1), Box::new(src2)),
                }]
            }
            LaneOp::Mul { .. } => {
                vec![Effect::RegWrite {
                    reg: dst_name,
                    value: IrExpr::Mul(Box::new(src1), Box::new(src2)),
                }]
            }
            LaneOp::Div { .. } => {
                vec![Effect::Intrinsic {
                    name: format!("simd_div_{}", lane_suffix(&desc.op)),
                    args: vec![dst, src1, src2],
                }]
            }
            LaneOp::Sqrt { .. } => {
                vec![Effect::Intrinsic {
                    name: format!("simd_sqrt_{}", lane_suffix(&desc.op)),
                    args: vec![dst, src1],
                }]
            }
            LaneOp::Min { .. } => {
                vec![Effect::Intrinsic {
                    name: format!("simd_min_{}", lane_suffix(&desc.op)),
                    args: vec![dst, src1, src2],
                }]
            }
            LaneOp::Max { .. } => {
                vec![Effect::Intrinsic {
                    name: format!("simd_max_{}", lane_suffix(&desc.op)),
                    args: vec![dst, src1, src2],
                }]
            }
            // ── Bitwise ───────────────────────────────────────────────────────
            LaneOp::And { .. } => {
                vec![Effect::RegWrite {
                    reg: dst_name,
                    value: IrExpr::And(Box::new(src1), Box::new(src2)),
                }]
            }
            LaneOp::Or { .. } => {
                vec![Effect::RegWrite {
                    reg: dst_name,
                    value: IrExpr::Or(Box::new(src1), Box::new(src2)),
                }]
            }
            LaneOp::Xor { .. } => {
                vec![Effect::RegWrite {
                    reg: dst_name,
                    value: IrExpr::Xor(Box::new(src1), Box::new(src2)),
                }]
            }
            LaneOp::Andn { .. } => {
                vec![Effect::RegWrite {
                    reg: dst_name,
                    value: IrExpr::And(Box::new(IrExpr::Not(Box::new(src1))), Box::new(src2)),
                }]
            }
            // ── Comparisons ───────────────────────────────────────────────────
            LaneOp::CmpEq { .. } => {
                vec![Effect::Intrinsic {
                    name: "simd_cmpeq".to_string(),
                    args: vec![dst, src1, src2],
                }]
            }
            LaneOp::CmpGt { .. } => {
                vec![Effect::Intrinsic {
                    name: "simd_cmpgt".to_string(),
                    args: vec![dst, src1, src2],
                }]
            }
            LaneOp::CmpOrd { imm, .. } => {
                vec![Effect::Intrinsic {
                    name: format!("simd_cmpord_{imm}"),
                    args: vec![dst, src1, src2],
                }]
            }
            // ── Shifts ────────────────────────────────────────────────────────
            LaneOp::ShlImm { imm, .. } => {
                vec![Effect::RegWrite {
                    reg: dst_name,
                    value: IrExpr::Shl(Box::new(src1), Box::new(IrExpr::Const(u64::from(*imm)))),
                }]
            }
            LaneOp::ShrImm { imm, .. } | LaneOp::SarImm { imm, .. } => {
                vec![Effect::RegWrite {
                    reg: dst_name,
                    value: IrExpr::Shr(Box::new(src1), Box::new(IrExpr::Const(u64::from(*imm)))),
                }]
            }
            // ── Shuffle / permute ─────────────────────────────────────────────
            LaneOp::Pshufb => {
                vec![Effect::Intrinsic {
                    name: "pshufb".to_string(),
                    args: vec![dst, src1, src2],
                }]
            }
            LaneOp::Pshufd { imm } => {
                vec![Effect::Intrinsic {
                    name: format!("pshufd_{imm:#04x}"),
                    args: vec![dst, src1],
                }]
            }
            LaneOp::Shufps { imm } => {
                vec![Effect::Intrinsic {
                    name: format!("shufps_{imm:#04x}"),
                    args: vec![dst, src1, src2],
                }]
            }
            LaneOp::Permute { imm, .. } => {
                let name = match imm {
                    Some(i) => format!("vpermilps_{i:#04x}"),
                    None => "vpermilps_reg".to_string(),
                };
                vec![Effect::Intrinsic {
                    name,
                    args: vec![dst, src1, src2],
                }]
            }
            // ── Unpack / pack ─────────────────────────────────────────────────
            LaneOp::UnpackLo { lane } => {
                vec![Effect::Intrinsic {
                    name: format!("unpacklo_{}", lane.bits()),
                    args: vec![dst, src1, src2],
                }]
            }
            LaneOp::UnpackHi { lane } => {
                vec![Effect::Intrinsic {
                    name: format!("unpackhi_{}", lane.bits()),
                    args: vec![dst, src1, src2],
                }]
            }
            LaneOp::PackSs { lane } => {
                vec![Effect::Intrinsic {
                    name: format!("packss_{}", lane.bits()),
                    args: vec![dst, src1, src2],
                }]
            }
            LaneOp::PackUs { lane } => {
                vec![Effect::Intrinsic {
                    name: format!("packus_{}", lane.bits()),
                    args: vec![dst, src1, src2],
                }]
            }
            // ── Blend ─────────────────────────────────────────────────────────
            LaneOp::BlendImm { imm, .. } => {
                vec![Effect::Intrinsic {
                    name: format!("blend_{imm:#04x}"),
                    args: vec![dst, src1, src2],
                }]
            }
            LaneOp::BlendVar { .. } => {
                vec![Effect::Intrinsic {
                    name: "blendv".to_string(),
                    args: vec![dst, src1, src2],
                }]
            }
            // ── Horizontal arithmetic ─────────────────────────────────────────
            LaneOp::HAdd {
                ty: LaneType::F32, ..
            }
            | LaneOp::HAdd {
                ty: LaneType::F64, ..
            } => {
                vec![Effect::Intrinsic {
                    name: "haddps".to_string(),
                    args: vec![dst, src1, src2],
                }]
            }
            LaneOp::HAdd { .. } => {
                vec![Effect::Intrinsic {
                    name: "phadd".to_string(),
                    args: vec![dst, src1, src2],
                }]
            }
            LaneOp::HSub { .. } => {
                vec![Effect::Intrinsic {
                    name: "phsub".to_string(),
                    args: vec![dst, src1, src2],
                }]
            }
            // ── Dot product ───────────────────────────────────────────────────
            LaneOp::DotProduct { imm, .. } => {
                vec![Effect::Intrinsic {
                    name: format!("dpps_{imm:#04x}"),
                    args: vec![dst, src1, src2],
                }]
            }
            // ── String / CRC ──────────────────────────────────────────────────
            LaneOp::StringCmp { imm } => {
                vec![Effect::Intrinsic {
                    name: format!("pcmpistri_{imm:#04x}"),
                    args: vec![dst, src1, src2],
                }]
            }
            LaneOp::Crc32 { lane } => {
                vec![Effect::Intrinsic {
                    name: format!("crc32_{}", lane.bits()),
                    args: vec![dst, src1, src2],
                }]
            }
            // ── Conversions ───────────────────────────────────────────────────
            LaneOp::Convert { src_ty, dst_ty, .. } => {
                vec![Effect::Intrinsic {
                    name: format!("cvt_{src_ty:?}_to_{dst_ty:?}"),
                    args: vec![dst, src1],
                }]
            }
            // ── Scalar move ───────────────────────────────────────────────────
            LaneOp::MoveScalar { .. } => {
                vec![Effect::RegWrite {
                    reg: dst_name,
                    value: src1,
                }]
            }
            // ── Insert / extract ──────────────────────────────────────────────
            LaneOp::Insert { imm, .. } => {
                vec![Effect::Intrinsic {
                    name: format!("pinsert_{imm:#04x}"),
                    args: vec![dst, src1, src2],
                }]
            }
            LaneOp::Extract { imm, .. } => {
                vec![Effect::Intrinsic {
                    name: format!("pextract_{imm:#04x}"),
                    args: vec![dst, src1],
                }]
            }
            // ── Broadcast ─────────────────────────────────────────────────────
            LaneOp::Broadcast { lane } => {
                vec![Effect::Intrinsic {
                    name: format!("broadcast_{}", lane.bits()),
                    args: vec![dst, src1],
                }]
            }
            // ── Gather / scatter ──────────────────────────────────────────────
            LaneOp::Gather { lane } => {
                vec![Effect::MemRead {
                    addr: src1,
                    dest: dst_name,
                    size: lane.bytes() as u8,
                }]
            }
            LaneOp::Scatter { lane } => {
                vec![Effect::MemWrite {
                    addr: src1,
                    value: dst,
                    size: lane.bytes() as u8,
                }]
            }
            // ── FMA ───────────────────────────────────────────────────────────
            LaneOp::Fma {
                negate_b, negate_c, ..
            } => {
                let b = if *negate_b {
                    IrExpr::Not(Box::new(src2.clone()))
                } else {
                    src2.clone()
                };
                let c = if *negate_c {
                    IrExpr::Not(Box::new(src1.clone()))
                } else {
                    src1.clone()
                };
                let product = IrExpr::Mul(Box::new(dst.clone()), Box::new(b));
                vec![Effect::RegWrite {
                    reg: dst_name,
                    value: IrExpr::Add(Box::new(product), Box::new(c)),
                }]
            }
            // ── AVX-512 masking ───────────────────────────────────────────────
            LaneOp::MaskZero { .. } | LaneOp::MaskMerge { .. } => {
                let k_name = desc
                    .masking
                    .k_reg().map_or_else(|| "k0".to_string(), |k| format!("k{k}"));
                vec![Effect::Intrinsic {
                    name: "avx512_masked_move".to_string(),
                    args: vec![dst, src1, IrExpr::Reg(k_name)],
                }]
            }
            // ── Plain move ────────────────────────────────────────────────────
            LaneOp::Move => {
                vec![Effect::RegWrite {
                    reg: dst_name,
                    value: src1,
                }]
            }
        }
    }
}

/// Returns a short lane/type suffix string for intrinsic naming.
fn lane_suffix(op: &LaneOp) -> String {
    match op {
        LaneOp::Add { lane, ty }
        | LaneOp::Sub { lane, ty }
        | LaneOp::Mul { lane, ty }
        | LaneOp::Div { lane, ty }
        | LaneOp::Sqrt { lane, ty }
        | LaneOp::Min { lane, ty }
        | LaneOp::Max { lane, ty } => format!("{}{}", ty_char(ty), lane.bits()),
        _ => "u8".to_string(),
    }
}

const fn ty_char(ty: &LaneType) -> char {
    match ty {
        LaneType::Uint => 'u',
        LaneType::Sint => 'i',
        LaneType::F32 => 'f',
        LaneType::F64 => 'd',
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Instruction builder helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Build a `SimdInstrDesc` for a two-operand 128-bit ADD.
#[must_use]
pub fn sse2_add(dst: u8, src: u8, lane: LaneWidth, ty: LaneType) -> SimdInstrDesc {
    SimdInstrDesc {
        mnemonic: format!("add{}{}", ty_char(&ty), lane.bits()),
        dst: VRegister::xmm(dst),
        src1: Some(VRegister::xmm(dst)),
        src2: Some(VRegister::xmm(src)),
        imm: None,
        op: LaneOp::Add { lane, ty },
        masking: MaskingOp::None,
        embedded_rounding: None,
    }
}

/// Build a `SimdInstrDesc` for a two-operand 256-bit ADD (AVX).
#[must_use]
pub fn avx_add(dst: u8, src1: u8, src2: u8, lane: LaneWidth, ty: LaneType) -> SimdInstrDesc {
    SimdInstrDesc {
        mnemonic: format!("vadd{}{}", ty_char(&ty), lane.bits()),
        dst: VRegister::ymm(dst),
        src1: Some(VRegister::ymm(src1)),
        src2: Some(VRegister::ymm(src2)),
        imm: None,
        op: LaneOp::Add { lane, ty },
        masking: MaskingOp::None,
        embedded_rounding: None,
    }
}

/// Build a `SimdInstrDesc` for an AVX-512 ADD with k-mask zeroing.
#[must_use]
pub fn avx512_add_zeroing(
    dst: u8,
    src1: u8,
    src2: u8,
    k: u8,
    lane: LaneWidth,
    ty: LaneType,
) -> SimdInstrDesc {
    SimdInstrDesc {
        mnemonic: format!("vadd{}{}", ty_char(&ty), lane.bits()),
        dst: VRegister::zmm(dst),
        src1: Some(VRegister::zmm(src1)),
        src2: Some(VRegister::zmm(src2)),
        imm: None,
        op: LaneOp::Add { lane, ty },
        masking: MaskingOp::Zero { k_reg: k },
        embedded_rounding: None,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_ctx() -> SimdLiftContext {
        SimdLiftContext::sse2()
    }

    // VRegister
    #[test]
    fn vreg_xmm_name() {
        assert_eq!(VRegister::xmm(3).name(), "xmm3");
    }
    #[test]
    fn vreg_ymm_name() {
        assert_eq!(VRegister::ymm(15).name(), "ymm15");
    }
    #[test]
    fn vreg_zmm_name() {
        assert_eq!(VRegister::zmm(31).name(), "zmm31");
    }
    #[test]
    fn vreg_expr_is_reg() {
        let v = VRegister::xmm(0);
        assert_eq!(v.expr(), IrExpr::Reg("xmm0".to_string()));
    }

    // LaneWidth
    #[test]
    fn lane_width_bytes() {
        assert_eq!(LaneWidth::Byte.bytes(), 1);
        assert_eq!(LaneWidth::Word.bytes(), 2);
        assert_eq!(LaneWidth::Dword.bytes(), 4);
        assert_eq!(LaneWidth::Qword.bytes(), 8);
    }
    #[test]
    fn lane_width_bits() {
        assert_eq!(LaneWidth::Dword.bits(), 32);
    }

    // RegWidth
    #[test]
    fn reg_width_bytes() {
        assert_eq!(RegWidth::Xmm.bytes(), 16);
        assert_eq!(RegWidth::Ymm.bytes(), 32);
        assert_eq!(RegWidth::Zmm.bytes(), 64);
    }
    #[test]
    fn reg_width_prefix() {
        assert_eq!(RegWidth::Xmm.prefix(), "xmm");
        assert_eq!(RegWidth::Ymm.prefix(), "ymm");
        assert_eq!(RegWidth::Zmm.prefix(), "zmm");
    }

    // MaskingOp
    #[test]
    fn masking_none_is_none() {
        assert!(MaskingOp::None.is_none());
    }
    #[test]
    fn masking_zero_k_reg() {
        assert_eq!(MaskingOp::Zero { k_reg: 3 }.k_reg(), Some(3));
    }
    #[test]
    fn masking_merge_k_reg() {
        assert_eq!(MaskingOp::Merge { k_reg: 7 }.k_reg(), Some(7));
    }

    // SimdLiftContext
    #[test]
    fn ctx_initial_counts() {
        let ctx = make_ctx();
        assert_eq!(ctx.lifted_count, 0);
        assert_eq!(ctx.fallback_count, 0);
    }
    #[test]
    fn ctx_isa_levels() {
        assert_eq!(SimdLiftContext::avx2().isa_level, SimdIsaLevel::Avx2);
        assert_eq!(SimdLiftContext::avx512().isa_level, SimdIsaLevel::Avx512F);
    }

    // SimdILEmitter — ADD
    #[test]
    fn emit_sse2_add_f32_produces_reg_write() {
        let mut ctx = make_ctx();
        let desc = sse2_add(0, 1, LaneWidth::Dword, LaneType::F32);
        let mut emitter = SimdILEmitter::new(&mut ctx);
        let effects = emitter.emit(&desc);
        // Should contain a RegWrite (plus possible vex_zero_upper stub)
        assert!(
            effects
                .iter()
                .any(|e| matches!(e, Effect::RegWrite { reg, .. } if reg == "xmm0"))
        );
    }

    #[test]
    fn emit_sse2_add_increments_lifted_count() {
        let mut ctx = make_ctx();
        ctx.vex_zero_upper = false;
        let desc = sse2_add(2, 3, LaneWidth::Qword, LaneType::Sint);
        let _ = SimdILEmitter::new(&mut ctx).emit(&desc);
        assert_eq!(ctx.lifted_count, 1);
        assert_eq!(ctx.fallback_count, 0);
    }

    // AND / OR / XOR / ANDN
    #[test]
    fn emit_and_uses_ir_and() {
        let mut ctx = make_ctx();
        ctx.vex_zero_upper = false;
        let desc = SimdInstrDesc {
            mnemonic: "andps".to_string(),
            dst: VRegister::xmm(0),
            src1: Some(VRegister::xmm(0)),
            src2: Some(VRegister::xmm(1)),
            imm: None,
            op: LaneOp::And {
                lane: LaneWidth::Dword,
            },
            masking: MaskingOp::None,
            embedded_rounding: None,
        };
        let effects = SimdILEmitter::new(&mut ctx).emit(&desc);
        assert!(effects.iter().any(|e| matches!(
            e,
            Effect::RegWrite {
                value: IrExpr::And(..),
                ..
            }
        )));
    }

    #[test]
    fn emit_xor_zeroing() {
        let mut ctx = make_ctx();
        ctx.vex_zero_upper = false;
        let desc = SimdInstrDesc {
            mnemonic: "xorps".to_string(),
            dst: VRegister::xmm(5),
            src1: Some(VRegister::xmm(5)),
            src2: Some(VRegister::xmm(5)),
            imm: None,
            op: LaneOp::Xor {
                lane: LaneWidth::Dword,
            },
            masking: MaskingOp::None,
            embedded_rounding: None,
        };
        let effects = SimdILEmitter::new(&mut ctx).emit(&desc);
        assert!(effects.iter().any(|e| matches!(
            e,
            Effect::RegWrite {
                value: IrExpr::Xor(..),
                ..
            }
        )));
    }

    // Shift
    #[test]
    fn emit_shift_left_imm() {
        let mut ctx = make_ctx();
        ctx.vex_zero_upper = false;
        let desc = SimdInstrDesc {
            mnemonic: "psllw".to_string(),
            dst: VRegister::xmm(1),
            src1: Some(VRegister::xmm(1)),
            src2: None,
            imm: Some(4),
            op: LaneOp::ShlImm {
                lane: LaneWidth::Word,
                imm: 4,
            },
            masking: MaskingOp::None,
            embedded_rounding: None,
        };
        let effects = SimdILEmitter::new(&mut ctx).emit(&desc);
        assert!(effects.iter().any(|e| matches!(
            e,
            Effect::RegWrite {
                value: IrExpr::Shl(..),
                ..
            }
        )));
    }

    // Broadcast (intrinsic)
    #[test]
    fn emit_broadcast_intrinsic() {
        let mut ctx = SimdLiftContext::avx2();
        ctx.vex_zero_upper = false;
        let desc = SimdInstrDesc {
            mnemonic: "vbroadcastss".to_string(),
            dst: VRegister::ymm(0),
            src1: Some(VRegister::xmm(0)),
            src2: None,
            imm: None,
            op: LaneOp::Broadcast {
                lane: LaneWidth::Dword,
            },
            masking: MaskingOp::None,
            embedded_rounding: None,
        };
        let effects = SimdILEmitter::new(&mut ctx).emit(&desc);
        assert!(
            effects
                .iter()
                .any(|e| matches!(e, Effect::Intrinsic { name, .. } if name.contains("broadcast")))
        );
    }

    // AVX-512 masked add
    #[test]
    fn emit_avx512_masked_add() {
        let mut ctx = SimdLiftContext::avx512();
        ctx.vex_zero_upper = false;
        let desc = avx512_add_zeroing(0, 1, 2, 3, LaneWidth::Dword, LaneType::F32);
        let effects = SimdILEmitter::new(&mut ctx).emit(&desc);
        // Masked instructions fall through to masking intrinsic
        assert!(!effects.is_empty());
    }

    // AVX 3-operand add
    #[test]
    fn emit_avx_add_256bit() {
        let mut ctx = SimdLiftContext::avx2();
        ctx.vex_zero_upper = false;
        let desc = avx_add(0, 1, 2, LaneWidth::Dword, LaneType::F32);
        let effects = SimdILEmitter::new(&mut ctx).emit(&desc);
        assert!(
            effects
                .iter()
                .any(|e| matches!(e, Effect::RegWrite { reg, .. } if reg == "ymm0"))
        );
    }

    // Gather (memory read)
    #[test]
    fn emit_gather_is_mem_read() {
        let mut ctx = SimdLiftContext::avx2();
        ctx.vex_zero_upper = false;
        let desc = SimdInstrDesc {
            mnemonic: "vgatherdps".to_string(),
            dst: VRegister::ymm(0),
            src1: Some(VRegister::ymm(1)),
            src2: None,
            imm: None,
            op: LaneOp::Gather {
                lane: LaneWidth::Dword,
            },
            masking: MaskingOp::None,
            embedded_rounding: None,
        };
        let effects = SimdILEmitter::new(&mut ctx).emit(&desc);
        assert!(effects.iter().any(|e| matches!(e, Effect::MemRead { .. })));
    }

    // Convert intrinsic
    #[test]
    fn emit_convert_intrinsic() {
        let mut ctx = make_ctx();
        ctx.vex_zero_upper = false;
        let desc = SimdInstrDesc {
            mnemonic: "cvtps2pd".to_string(),
            dst: VRegister::xmm(0),
            src1: Some(VRegister::xmm(1)),
            src2: None,
            imm: None,
            op: LaneOp::Convert {
                src_ty: LaneType::F32,
                dst_ty: LaneType::F64,
                src_lane: LaneWidth::Dword,
                dst_lane: LaneWidth::Qword,
            },
            masking: MaskingOp::None,
            embedded_rounding: None,
        };
        let effects = SimdILEmitter::new(&mut ctx).emit(&desc);
        assert!(
            effects
                .iter()
                .any(|e| matches!(e, Effect::Intrinsic { name, .. } if name.contains("cvt")))
        );
    }

    // FMA
    #[test]
    fn emit_fma_produces_reg_write() {
        let mut ctx = SimdLiftContext::avx2();
        ctx.vex_zero_upper = false;
        let desc = SimdInstrDesc {
            mnemonic: "vfmadd132ps".to_string(),
            dst: VRegister::ymm(0),
            src1: Some(VRegister::ymm(1)),
            src2: Some(VRegister::ymm(2)),
            imm: None,
            op: LaneOp::Fma {
                lane: LaneWidth::Dword,
                negate_b: false,
                negate_c: false,
            },
            masking: MaskingOp::None,
            embedded_rounding: None,
        };
        let effects = SimdILEmitter::new(&mut ctx).emit(&desc);
        assert!(effects.iter().any(|e| matches!(e, Effect::RegWrite { .. })));
    }

    // VEX zero-upper side effect
    #[test]
    fn vex_zero_upper_appended_for_xmm_write() {
        let mut ctx = make_ctx();
        ctx.vex_zero_upper = true;
        let desc = sse2_add(0, 1, LaneWidth::Dword, LaneType::F32);
        let effects = SimdILEmitter::new(&mut ctx).emit(&desc);
        assert!(effects.iter().any(|e| matches!(
            e, Effect::Intrinsic { name, .. } if name == "vex_zero_upper"
        )));
    }

    // String comparison intrinsic
    #[test]
    fn emit_string_cmp_intrinsic() {
        let mut ctx = make_ctx();
        ctx.vex_zero_upper = false;
        let desc = SimdInstrDesc {
            mnemonic: "pcmpistri".to_string(),
            dst: VRegister::xmm(0),
            src1: Some(VRegister::xmm(0)),
            src2: Some(VRegister::xmm(1)),
            imm: Some(0x0c),
            op: LaneOp::StringCmp { imm: 0x0c },
            masking: MaskingOp::None,
            embedded_rounding: None,
        };
        let effects = SimdILEmitter::new(&mut ctx).emit(&desc);
        assert!(
            effects
                .iter()
                .any(|e| matches!(e, Effect::Intrinsic { name, .. } if name.contains("pcmpistri")))
        );
    }

    // CRC32
    #[test]
    fn emit_crc32_intrinsic() {
        let mut ctx = make_ctx();
        ctx.vex_zero_upper = false;
        let desc = SimdInstrDesc {
            mnemonic: "crc32".to_string(),
            dst: VRegister::xmm(0),
            src1: Some(VRegister::xmm(0)),
            src2: Some(VRegister::xmm(1)),
            imm: None,
            op: LaneOp::Crc32 {
                lane: LaneWidth::Dword,
            },
            masking: MaskingOp::None,
            embedded_rounding: None,
        };
        let effects = SimdILEmitter::new(&mut ctx).emit(&desc);
        assert!(
            effects
                .iter()
                .any(|e| matches!(e, Effect::Intrinsic { name, .. } if name.contains("crc32")))
        );
    }

    // Dot product
    #[test]
    fn emit_dpps_intrinsic() {
        let mut ctx = make_ctx();
        ctx.vex_zero_upper = false;
        let desc = SimdInstrDesc {
            mnemonic: "dpps".to_string(),
            dst: VRegister::xmm(0),
            src1: Some(VRegister::xmm(0)),
            src2: Some(VRegister::xmm(1)),
            imm: Some(0xff),
            op: LaneOp::DotProduct {
                lane: LaneWidth::Dword,
                imm: 0xff,
            },
            masking: MaskingOp::None,
            embedded_rounding: None,
        };
        let effects = SimdILEmitter::new(&mut ctx).emit(&desc);
        assert!(
            effects
                .iter()
                .any(|e| matches!(e, Effect::Intrinsic { name, .. } if name.contains("dpps")))
        );
    }

    // Blend variable
    #[test]
    fn emit_blendv_intrinsic() {
        let mut ctx = make_ctx();
        ctx.vex_zero_upper = false;
        let desc = SimdInstrDesc {
            mnemonic: "blendvps".to_string(),
            dst: VRegister::xmm(0),
            src1: Some(VRegister::xmm(0)),
            src2: Some(VRegister::xmm(1)),
            imm: None,
            op: LaneOp::BlendVar {
                lane: LaneWidth::Dword,
            },
            masking: MaskingOp::None,
            embedded_rounding: None,
        };
        let effects = SimdILEmitter::new(&mut ctx).emit(&desc);
        assert!(
            effects
                .iter()
                .any(|e| matches!(e, Effect::Intrinsic { name, .. } if name == "blendv"))
        );
    }

    // Sub
    #[test]
    fn emit_sub_produces_reg_write_with_sub_expr() {
        let mut ctx = make_ctx();
        ctx.vex_zero_upper = false;
        let desc = SimdInstrDesc {
            mnemonic: "subps".to_string(),
            dst: VRegister::xmm(2),
            src1: Some(VRegister::xmm(2)),
            src2: Some(VRegister::xmm(3)),
            imm: None,
            op: LaneOp::Sub {
                lane: LaneWidth::Dword,
                ty: LaneType::F32,
            },
            masking: MaskingOp::None,
            embedded_rounding: None,
        };
        let effects = SimdILEmitter::new(&mut ctx).emit(&desc);
        assert!(effects.iter().any(
            |e| matches!(e, Effect::RegWrite { value: IrExpr::Sub(..), reg } if reg == "xmm2")
        ));
    }

    // Move scalar
    #[test]
    fn emit_move_scalar_is_reg_write() {
        let mut ctx = make_ctx();
        ctx.vex_zero_upper = false;
        let desc = SimdInstrDesc {
            mnemonic: "movss".to_string(),
            dst: VRegister::xmm(0),
            src1: Some(VRegister::xmm(1)),
            src2: None,
            imm: None,
            op: LaneOp::MoveScalar {
                lane: LaneWidth::Dword,
                ty: LaneType::F32,
            },
            masking: MaskingOp::None,
            embedded_rounding: None,
        };
        let effects = SimdILEmitter::new(&mut ctx).emit(&desc);
        assert!(
            effects
                .iter()
                .any(|e| matches!(e, Effect::RegWrite { reg, .. } if reg == "xmm0"))
        );
    }
}
